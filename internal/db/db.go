package db

import (
	"path/filepath"
	db_types "vulndetector/internal/db/types"

	"go.etcd.io/bbolt"
	bolt "go.etcd.io/bbolt"
)

// Global configuration: list of OCI repositories to try (in priority order)
var Repositories = []string{
	"mirror.gcr.io/aquasec/trivy-db:2",
	"ghcr.io/aquasecurity/trivy-db:2",
}

const (
	DstDir           = "./bugs_db_dir" // Destination directory
	DBFilename       = "bugs.db"       // Renamed DB file
	MetadataFilename = "metadata.json" // Metadata file name
)

type DB struct {
	bolt *bbolt.DB
}

// NewDB opens the Bolt DB at the correct location.
func NewDB() (DB, error) {
	dbPath := filepath.Join(DstDir, DBFilename)

	bdb, err := OpenBoltDB(dbPath)
	if err != nil {
		return DB{}, err
	}
	return DB{
		bolt: bdb,
	}, nil
}

// Close closes the underlying Bolt DB.
func (d *DB) Close() error {
	return d.bolt.Close()
}

// // GetAdvisories returns all vulnerability advisories from the DB.
// func (d *DB) GetAdvisories() ([]db_types.Vulnerability, error) {
// 	return LoadAdvisories(d.bolt)
// }

func (d *DB) ListAllBuckets() ([]string, error) {
	return ListBuckets(d.bolt)
}

func (d *DB) GetAdvisoriesForSource(source, pkgName string) ([]db_types.Advisory, error) {
	return LoadAdvisoriesForSource(d.bolt, source, pkgName)
}

type Operation interface {
	BatchUpdate(fn func(*bolt.Tx) error) (err error)

	GetVulnerabilityDetail(cveID string) (detail map[db_types.SourceID]db_types.VulnerabilityDetail, err error)
	PutVulnerabilityDetail(tx *bolt.Tx, vulnerabilityID string, source db_types.SourceID,
		vulnerability db_types.VulnerabilityDetail) (err error)
	DeleteVulnerabilityDetailBucket() (err error)

	ForEachAdvisory(sources []string, pkgName string) (value map[string]db_types.Value, err error)
	GetAdvisories(source string, pkgName string) (advisories []db_types.Advisory, err error)

	PutVulnerabilityID(tx *bolt.Tx, vulnerabilityID string) (err error)
	ForEachVulnerabilityID(fn func(tx *bolt.Tx, cveID string) error) (err error)

	PutVulnerability(tx *bolt.Tx, vulnerabilityID string, vulnerability db_types.Vulnerability) (err error)
	GetVulnerability(vulnerabilityID string) (vulnerability db_types.Vulnerability, err error)

	SaveAdvisoryDetails(tx *bolt.Tx, cveID string) (err error)
	PutAdvisoryDetail(tx *bolt.Tx, vulnerabilityID, pkgName string, nestedBktNames []string, advisory interface{}) (err error)
	DeleteAdvisoryDetailBucket() error

	PutDataSource(tx *bolt.Tx, bktName string, source db_types.DataSource) (err error)

	// For Red Hat
	PutRedHatRepositories(tx *bolt.Tx, repository string, cpeIndices []int) (err error)
	PutRedHatNVRs(tx *bolt.Tx, nvr string, cpeIndices []int) (err error)
	PutRedHatCPEs(tx *bolt.Tx, cpeIndex int, cpe string) (err error)
	RedHatRepoToCPEs(repository string) (cpeIndices []int, err error)
	RedHatNVRToCPEs(nvr string) (cpeIndices []int, err error)
}
