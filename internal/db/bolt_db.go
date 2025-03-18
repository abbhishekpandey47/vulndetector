package db

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	db_types "vulndetector/internal/db/types"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"
)

const (
	dataSourceBucket = "data-source"
	advisoriesBucket = "vulnerability"
)

// OpenBoltDB opens a Bolt DB at the given path.
func OpenBoltDB(path string) (*bolt.DB, error) {
	db, err := bolt.Open(path, 0644, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open bolt db: %w", err)
	}
	return db, nil
}

// LoadAdvisories loads all advisories from the Bolt DB.
// func LoadAdvisories(bdb *bolt.DB) ([]db_types.Vulnerability, error) {
// 	var vulnerabilities []db_types.Vulnerability
// 	err := bdb.View(func(tx *bolt.Tx) error {
// 		b := tx.Bucket([]byte(advisoriesBucket))
// 		if b == nil {
// 			return fmt.Errorf("bucket %s not found", advisoriesBucket)
// 		}
// 		return b.ForEach(func(k, v []byte) error {
// 			var adv db_types.Vulnerability
// 			if err := json.Unmarshal(v, &adv); err != nil {
// 				log.Printf("[WARN] Error unmarshalling key %s: %v", k, err)
// 				return err
// 			}
// 			// Set the vulnerability ID to the key if not already set.
// 			if adv.VulnerabilityID == "" {
// 				adv.VulnerabilityID = string(k)
// 			}
// 			vulnerabilities = append(vulnerabilities, adv)
// 			return nil
// 		})
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	return vulnerabilities, nil
// }

// ListBuckets returns a slice of all top-level bucket names in the Bolt DB.
func ListBuckets(bdb *bolt.DB) ([]string, error) {
	var buckets []string
	err := bdb.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			buckets = append(buckets, string(name))
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list buckets: %w", err)
	}
	return buckets, nil
}

// func (dbc Config) PutAdvisory(tx *bolt.Tx, bktNames []string, key string, advisory interface{}) error {
// 	if err := dbc.put(tx, bktNames, key, advisory); err != nil {
// 		return oops.With("key", key).Wrapf(err, "failed to put advisory")
// 	}
// 	return nil
// }

func LoadAdvisoriesForSource(bdb *bolt.DB, source, pkgName string) ([]db_types.Advisory, error) {
	eb := oops.With("source", source).With("package_name", pkgName)
	advisories, err := ForEachAdvisory(bdb, []string{source}, pkgName)
	if err != nil {
		return nil, eb.Wrapf(err, "advisory foreach error")
	}
	if len(advisories) == 0 {
		return nil, nil
	}

	var results []db_types.Advisory
	for vulnID, v := range advisories {
		var advisory db_types.Advisory
		if err = json.Unmarshal(v.Content, &advisory); err != nil {
			return nil, eb.With("vuln_id", vulnID).Wrapf(err, "json unmarshal error")
		}

		advisory.VulnerabilityID = vulnID
		if v.Source != (db_types.DataSource{}) {
			advisory.DataSource = &db_types.DataSource{
				ID:   v.Source.ID,
				Name: v.Source.Name,
				URL:  v.Source.URL,
			}
		}

		results = append(results, advisory)
	}
	return results, nil
}

func ForEachAdvisory(bdb *bolt.DB, sources []string, pkgName string) (map[string]db_types.Value, error) {
	return forEach(bdb, append(sources, pkgName))
}

/******* Helper Functions ********/

func forEach(bdb *bolt.DB, bktNames []string) (map[string]db_types.Value, error) {
	eb := oops.With("bucket_names", bktNames)
	if len(bktNames) < 2 {
		return nil, eb.Errorf("bucket must be nested")
	}
	rootBucket, nestedBuckets := bktNames[0], bktNames[1:]

	values := map[string]db_types.Value{}
	err := bdb.View(func(tx *bolt.Tx) error {
		var rootBuckets []string

		if strings.Contains(rootBucket, "::") {
			// e.g. "pip::", "rubygems::"
			prefix := []byte(rootBucket)
			c := tx.Cursor()
			for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
				rootBuckets = append(rootBuckets, string(k))
			}
		} else {
			// e.g. "GitHub Security Advisory Composer"
			rootBuckets = append(rootBuckets, rootBucket)
		}

		for _, r := range rootBuckets {
			root := tx.Bucket([]byte(r))
			if root == nil {
				continue
			}

			source, err := getDataSource(bdb, tx, r)
			if err != nil {
				//log.WithPrefix("db").Debug("Data source error", log.Err(err))
			}

			bkt := root
			for _, nestedBkt := range nestedBuckets {
				bkt = bkt.Bucket([]byte(nestedBkt))
				if bkt == nil {
					break
				}
			}
			if bkt == nil {
				continue
			}

			err = bkt.ForEach(func(k, v []byte) error {
				if len(v) == 0 {
					return nil
				}
				// Copy the byte slice so it can be used outside of the current transaction
				copiedContent := make([]byte, len(v))
				copy(copiedContent, v)

				values[string(k)] = db_types.Value{
					Source:  source,
					Content: copiedContent,
				}
				return nil
			})
			if err != nil {
				return eb.Wrapf(err, "db foreach error")
			}
		}
		return nil
	})
	if err != nil {
		return nil, eb.Wrapf(err, "failed to get all key/value in the specified bucket")
	}
	return values, nil
}

func getDataSource(bdb *bolt.DB, tx *bolt.Tx, bktName string) (db_types.DataSource, error) {
	eb := oops.With("root_bucket", dataSourceBucket).With("bucket_name", bktName)
	bucket := tx.Bucket([]byte(dataSourceBucket))
	if bucket == nil {
		return db_types.DataSource{}, nil
	}

	b := bucket.Get([]byte(bktName))
	if b == nil {
		return db_types.DataSource{}, nil
	}

	var source db_types.DataSource
	if err := json.Unmarshal(b, &source); err != nil {
		return db_types.DataSource{}, eb.Wrapf(err, "json unmarshal error")
	}

	return source, nil
}
