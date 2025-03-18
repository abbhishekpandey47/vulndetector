package db_types

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
	db_langTypes "vulndetector/internal/db/langTypes"

	"github.com/opencontainers/go-digest"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

type RenderedCause struct {
	Raw         string `json:",omitempty"`
	Highlighted string `json:",omitempty"`
}

type Occurrence struct {
	Resource string `json:",omitempty"`
	Filename string `json:",omitempty"`
	Location Location
}

type Code struct {
	Lines []Line
}

type Line struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation"`
	Truncated   bool   `json:"Truncated"`
	Highlighted string `json:"Highlighted,omitempty"`
	FirstCause  bool   `json:"FirstCause"`
	LastCause   bool   `json:"LastCause"`
}

type CauseMetadata struct {
	Resource      string        `json:",omitempty"`
	Provider      string        `json:",omitempty"`
	Service       string        `json:",omitempty"`
	StartLine     int           `json:",omitempty"`
	EndLine       int           `json:",omitempty"`
	Code          Code          `json:",omitempty"`
	Occurrences   []Occurrence  `json:",omitempty"`
	RenderedCause RenderedCause `json:",omitempty"`
}

type ResultClass string

const (
	ClassUnknown     ResultClass = "unknown"
	ClassOSPkg       ResultClass = "os-pkgs"      // For detected packages and vulnerabilities in OS packages
	ClassLangPkg     ResultClass = "lang-pkgs"    // For detected packages and vulnerabilities in language-specific packages
	ClassConfig      ResultClass = "config"       // For detected misconfigurations
	ClassSecret      ResultClass = "secret"       // For detected secrets
	ClassLicense     ResultClass = "license"      // For detected package licenses
	ClassLicenseFile ResultClass = "license-file" // For detected licenses in files
	ClassCustom      ResultClass = "custom"
)

type Results []Result

type MisconfSummary struct {
	Successes int
	Failures  int
}

func (s MisconfSummary) Empty() bool {
	return s.Successes == 0 && s.Failures == 0
}

type LicenseCategory string

const (
	CategoryForbidden    LicenseCategory = "forbidden"
	CategoryRestricted   LicenseCategory = "restricted"
	CategoryReciprocal   LicenseCategory = "reciprocal"
	CategoryNotice       LicenseCategory = "notice"
	CategoryPermissive   LicenseCategory = "permissive"
	CategoryUnencumbered LicenseCategory = "unencumbered"
	CategoryUnknown      LicenseCategory = "unknown"
)

type DetectedLicense struct {
	// Severity is the consistent parameter indicating how severe the issue is
	Severity string

	// Category holds the license category such as "forbidden"
	Category LicenseCategory

	// PkgName holds a package name of the license.
	// It will be empty if FilePath is filled.
	PkgName string

	// PkgName holds a file path of the license.
	// It will be empty if PkgName is filled.
	FilePath string // for file license

	// Name holds a detected license name
	Name string

	// Text holds a long license text if Trivy detects a license name as a license text
	Text string

	// Confidence is level of the match. The confidence level is between 0.0 and 1.0, with 1.0 indicating an
	// exact match and 0.0 indicating a complete mismatch
	Confidence float64

	// Link is a SPDX link of the license
	Link string
}

func (DetectedLicense) findingType() FindingType { return FindingTypeLicense }

type SecretRuleCategory string

type Secret struct {
	FilePath string
	Findings []SecretFinding
}

type SecretFinding struct {
	RuleID    string
	Category  SecretRuleCategory
	Severity  string
	Title     string
	StartLine int
	EndLine   int
	Code      Code
	Match     string
	Layer     Layer `json:",omitempty"`
}

// CustomResource holds the analysis result from a custom analyzer.
// It is for extensibility and not used in OSS.
type CustomResource struct {
	Type     string
	FilePath string
	Layer    Layer
	Data     any
}

type DetectedSecret SecretFinding

func (DetectedSecret) findingType() FindingType { return FindingTypeSecret }

// Result holds a target and detected vulnerabilities
type Result struct {
	Target            string                     `json:"Target"`
	Class             ResultClass                `json:"Class,omitempty"`
	Type              db_langTypes.TargetType    `json:"Type,omitempty"`
	Packages          []Package                  `json:"Packages,omitempty"`
	Vulnerabilities   []DetectedVulnerability    `json:"Vulnerabilities,omitempty"`
	MisconfSummary    *MisconfSummary            `json:"MisconfSummary,omitempty"`
	Misconfigurations []DetectedMisconfiguration `json:"Misconfigurations,omitempty"`
	Secrets           []DetectedSecret           `json:"Secrets,omitempty"`
	Licenses          []DetectedLicense          `json:"Licenses,omitempty"`
	CustomResources   []CustomResource           `json:"CustomResources,omitempty"`

	// ModifiedFindings holds a list of findings that have been modified from their original state.
	// This can include vulnerabilities that have been marked as ignored, not affected, or have had
	// their severity adjusted. It's still in an experimental stage and may change in the future.
	ModifiedFindings []ModifiedFinding `json:"ExperimentalModifiedFindings,omitempty"`
}

type Packages []Package

func (pkg *Package) Empty() bool {
	return pkg.Name == "" || pkg.Version == ""
}

func (pkgs Packages) Len() int {
	return len(pkgs)
}

func (pkgs Packages) Swap(i, j int) {
	pkgs[i], pkgs[j] = pkgs[j], pkgs[i]
}

func (pkgs Packages) Less(i, j int) bool {
	switch {
	case pkgs[i].Relationship != pkgs[j].Relationship:
		if pkgs[i].Relationship == RelationshipUnknown {
			return false
		} else if pkgs[j].Relationship == RelationshipUnknown {
			return true
		}
		return pkgs[i].Relationship < pkgs[j].Relationship
	case pkgs[i].Name != pkgs[j].Name:
		return pkgs[i].Name < pkgs[j].Name
	case pkgs[i].Version != pkgs[j].Version:
		return pkgs[i].Version < pkgs[j].Version
	}
	return pkgs[i].FilePath < pkgs[j].FilePath
}

func (apps Applications) Len() int {
	return len(apps)
}

func (apps Applications) Swap(i, j int) {
	apps[i], apps[j] = apps[j], apps[i]
}

func (apps Applications) Less(i, j int) bool {
	switch {
	case apps[i].Type != apps[j].Type:
		return apps[i].Type < apps[j].Type
	case apps[i].FilePath != apps[j].FilePath:
		return apps[i].FilePath < apps[j].FilePath
	default:
		return len(apps[i].Packages) < len(apps[j].Packages)
	}
}

// Ecosystem represents language-specific ecosystem
type Ecosystem string

const (
	// Data source
	NVD                   SourceID = "nvd"
	RedHat                SourceID = "redhat"
	RedHatOVAL            SourceID = "redhat-oval"
	Debian                SourceID = "debian"
	Ubuntu                SourceID = "ubuntu"
	CentOS                SourceID = "centos"
	Rocky                 SourceID = "rocky"
	Fedora                SourceID = "fedora"
	Amazon                SourceID = "amazon"
	OracleOVAL            SourceID = "oracle-oval"
	SuseCVRF              SourceID = "suse-cvrf"
	Alpine                SourceID = "alpine"
	ArchLinux             SourceID = "arch-linux"
	Alma                  SourceID = "alma"
	AzureLinux            SourceID = "azure"
	CBLMariner            SourceID = "cbl-mariner"
	Photon                SourceID = "photon"
	RubySec               SourceID = "ruby-advisory-db"
	PhpSecurityAdvisories SourceID = "php-security-advisories"
	NodejsSecurityWg      SourceID = "nodejs-security-wg"
	GHSA                  SourceID = "ghsa"
	GLAD                  SourceID = "glad"
	OSV                   SourceID = "osv"
	Wolfi                 SourceID = "wolfi"
	Chainguard            SourceID = "chainguard"
	BitnamiVulndb         SourceID = "bitnami"
	K8sVulnDB             SourceID = "k8s"
	GoVulnDB              SourceID = "govulndb"
	Aqua                  SourceID = "aqua"

	// Ecosystem
	Unknown    Ecosystem = "unknown"
	Npm        Ecosystem = "npm"
	Composer   Ecosystem = "composer"
	Pip        Ecosystem = "pip"
	RubyGems   Ecosystem = "rubygems"
	Cargo      Ecosystem = "cargo"
	NuGet      Ecosystem = "nuget"
	Maven      Ecosystem = "maven"
	Go         Ecosystem = "go"
	Conan      Ecosystem = "conan"
	Erlang     Ecosystem = "erlang"
	Pub        Ecosystem = "pub"
	Swift      Ecosystem = "swift"
	Cocoapods  Ecosystem = "cocoapods"
	Bitnami    Ecosystem = "bitnami"
	Kubernetes Ecosystem = "k8s"
)

var Ecosystems = []Ecosystem{
	Npm,
	Composer,
	Pip,
	RubyGems,
	Cargo,
	NuGet,
	Maven,
	Go,
	Conan,
	Erlang,
	Pub,
	Swift,
	Cocoapods,
	Bitnami,
	Kubernetes,
}

// AllSourceIDs lists all supported vulnerability source IDs in order of precedence.
// When searching for vulnerability details (Severity, Title, Description, and CWE-IDs),
// the sources are checked in this order until valid data is found.
// For example, if severity data is missing in NVD, it will check Red Hat next,
// continuing through the list until it finds a valid severity value.
var AllSourceIDs = []SourceID{
	NVD,
	RedHat,
	RedHatOVAL,
	Debian,
	Ubuntu,
	Alpine,
	Amazon,
	OracleOVAL,
	SuseCVRF,
	Photon,
	ArchLinux,
	Alma,
	Rocky,
	CBLMariner,
	AzureLinux,
	RubySec,
	PhpSecurityAdvisories,
	NodejsSecurityWg,
	GHSA,
	GLAD,
	Aqua,
	OSV,
	K8sVulnDB,
	Wolfi,
	Chainguard,
	BitnamiVulndb,
	GoVulnDB,
}

type VendorSeverity map[SourceID]Severity

type CVSS struct {
	V2Vector  string  `json:"V2Vector,omitempty"`
	V3Vector  string  `json:"V3Vector,omitempty"`
	V40Vector string  `json:"V40Vector,omitempty"`
	V2Score   float64 `json:"V2Score,omitempty"`
	V3Score   float64 `json:"V3Score,omitempty"`
	V40Score  float64 `json:"V40Score,omitempty"`
}

type CVSSVector struct {
	V2 string `json:"v2,omitempty"`
	V3 string `json:"v3,omitempty"`
}

type VendorCVSS map[SourceID]CVSS

type Location struct {
	StartLine int `json:",omitempty"`
	EndLine   int `json:",omitempty"`
}

type Locations []Location

func (locs Locations) Len() int { return len(locs) }
func (locs Locations) Less(i, j int) bool {
	return locs[i].StartLine < locs[j].StartLine
}
func (locs Locations) Swap(i, j int) { locs[i], locs[j] = locs[j], locs[i] }

type ExternalRef struct {
	Type RefType
	URL  string
}

type RefType string

const (
	RefVCS   RefType = "vcs"
	RefOther RefType = "other"
)

// Vulnerability represents an advisory for a given package.
// type Vulnerability struct {
// 	// Unique ID of the vulnerability.
// 	VulnerabilityID string `json:"vulnerability_id"`
// 	// The affected package name.
// 	PackageName string `json:"package_name"`
// 	// VulnerableConstraint describes the version constraint (e.g. "< 2.0.0").
// 	VulnerableConstraint string `json:"vulnerable_constraint"`
// 	// FixedVersion is the version that fixes the vulnerability.
// 	FixedVersion string `json:"fixed_version"`
// 	// DataSource identifies where this advisory came from.
// 	DataSource string `json:"data_source"`
// }

type Vulnerability struct {
	Title            string         `json:",omitempty"`
	Description      string         `json:",omitempty"`
	Severity         string         `json:",omitempty"` // Selected from VendorSeverity, depending on a scan target
	CweIDs           []string       `json:",omitempty"` // e.g. CWE-78, CWE-89
	VendorSeverity   VendorSeverity `json:",omitempty"`
	CVSS             VendorCVSS     `json:",omitempty"`
	References       []string       `json:",omitempty"`
	PublishedDate    *time.Time     `json:",omitempty"` // Take from NVD
	LastModifiedDate *time.Time     `json:",omitempty"` // Take from NVD

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom interface{} `json:",omitempty"`
}

type LastUpdated struct {
	Date time.Time
}
type VulnerabilityDetail struct {
	ID               string     `json:",omitempty"` // e.g. CVE-2019-8331, OSVDB-104365
	CvssScore        float64    `json:",omitempty"`
	CvssVector       string     `json:",omitempty"`
	CvssScoreV3      float64    `json:",omitempty"`
	CvssVectorV3     string     `json:",omitempty"`
	CvssScoreV40     float64    `json:",omitempty"`
	CvssVectorV40    string     `json:",omitempty"`
	Severity         Severity   `json:",omitempty"`
	SeverityV3       Severity   `json:",omitempty"`
	SeverityV40      Severity   `json:",omitempty"`
	CweIDs           []string   `json:",omitempty"` // e.g. CWE-78, CWE-89
	References       []string   `json:",omitempty"`
	Title            string     `json:",omitempty"`
	Description      string     `json:",omitempty"`
	PublishedDate    *time.Time `json:",omitempty"` // Take from NVD
	LastModifiedDate *time.Time `json:",omitempty"` // Take from NVD
}

// Qualifier represents a single key=value qualifier in the package url
type Qualifier struct {
	Key   string
	Value string
}

// Qualifiers is a slice of key=value pairs, with order preserved as it appears
// in the package URL.
type Qualifiers []Qualifier

// PackageURL is the struct representation of the parts that make a package url
type PackageURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers Qualifiers
	Subpath    string
}

// PkgIdentifier represents a software identifiers in one of more of the supported formats.
type PkgIdentifier struct {
	UID    string      `json:",omitempty"` // Calculated by the package struct
	PURL   *PackageURL `json:"-"`
	BOMRef string      `json:",omitempty"` // For CycloneDX
}

// BuildInfo represents information under /root/buildinfo in RHEL
type BuildInfo struct {
	ContentSets []string `json:",omitempty"`
	Nvr         string   `json:",omitempty"`
	Arch        string   `json:",omitempty"`
}

type Package struct {
	ID                 string        `json:",omitempty"`
	Name               string        `json:",omitempty"`
	Identifier         PkgIdentifier `json:",omitempty"`
	Version            string        `json:",omitempty"`
	Release            string        `json:",omitempty"`
	Epoch              int           `json:",omitempty"`
	Arch               string        `json:",omitempty"`
	Dev                bool          `json:",omitempty"`
	SrcName            string        `json:",omitempty"`
	SrcVersion         string        `json:",omitempty"`
	SrcRelease         string        `json:",omitempty"`
	SrcEpoch           int           `json:",omitempty"`
	Licenses           []string      `json:",omitempty"`
	Maintainer         string        `json:",omitempty"`
	ExternalReferences []ExternalRef `json:"-" hash:"ignore"`

	Modularitylabel string     `json:",omitempty"` // only for Red Hat based distributions
	BuildInfo       *BuildInfo `json:",omitempty"` // only for Red Hat

	Indirect     bool         `json:",omitempty"` // Deprecated: Use relationship. Kept for backward compatibility.
	Relationship Relationship `json:",omitempty"`

	// Dependencies of this package
	// Note:　it may have interdependencies, which may lead to infinite loops.
	DependsOn []string `json:",omitempty"`

	Layer Layer `json:",omitempty"`

	// Each package metadata have the file path, while the package from lock files does not have.
	FilePath string `json:",omitempty"`

	// This is required when using SPDX formats. Otherwise, it will be empty.
	Digest digest.Digest `json:",omitempty"`

	// lines from the lock file where the dependency is written
	Locations Locations `json:",omitempty"`

	// Files installed by the package
	InstalledFiles []string `json:",omitempty"`
}

// DetectedVulnerability holds the information of detected vulnerabilities
type DetectedVulnerability struct {
	VulnerabilityID  string        `json:",omitempty"`
	VendorIDs        []string      `json:",omitempty"`
	PkgID            string        `json:",omitempty"` // It is used to construct dependency graph.
	PkgName          string        `json:",omitempty"`
	PkgPath          string        `json:",omitempty"` // This field is populated in the case of language-specific packages such as egg/wheel and gemspec
	PkgIdentifier    PkgIdentifier `json:",omitempty"`
	InstalledVersion string        `json:",omitempty"`
	FixedVersion     string        `json:",omitempty"`
	Status           Status        `json:",omitempty"`
	Layer            Layer         `json:",omitempty"`
	SeveritySource   SourceID      `json:",omitempty"`
	PrimaryURL       string        `json:",omitempty"`

	// DataSource holds where the advisory comes from
	DataSource *DataSource `json:",omitempty"`

	// Custom is for extensibility and not supposed to be used in OSS
	Custom any `json:",omitempty"`

	// Embed vulnerability details
	Vulnerability
}

// SourceID represents data source such as NVD.
type SourceID string

type DataSource struct {
	ID   SourceID `json:",omitempty"`
	Name string   `json:",omitempty"`
	URL  string   `json:",omitempty"`
}

type Value struct {
	Source  DataSource
	Content []byte
}

type Advisory struct {
	VulnerabilityID string   `json:",omitempty"` // CVE-ID or vendor ID
	VendorIDs       []string `json:",omitempty"` // e.g. RHSA-ID and DSA-ID

	Arches []string `json:",omitempty"`

	// It is filled only when FixedVersion is empty since it is obvious the state is "Fixed" when FixedVersion is not empty.
	// e.g. Will not fix and Affected
	Status Status `json:"-"`

	// Trivy DB has "vulnerability" bucket and severities are usually stored in the bucket per a vulnerability ID.
	// In some cases, the advisory may have multiple severities depending on the packages.
	// For example, CVE-2015-2328 in Debian has "unimportant" for mongodb and "low" for pcre3.
	// e.g. https://security-tracker.debian.org/tracker/CVE-2015-2328
	Severity Severity `json:",omitempty"`

	// Versions for os package
	FixedVersion    string `json:",omitempty"`
	AffectedVersion string `json:",omitempty"` // Only for Arch Linux

	// MajorVersion ranges for language-specific package
	// Some advisories provide VulnerableVersions only, others provide PatchedVersions and UnaffectedVersions
	VulnerableVersions []string `json:",omitempty"`
	PatchedVersions    []string `json:",omitempty"`
	UnaffectedVersions []string `json:",omitempty"`

	// DataSource holds where the advisory comes from
	DataSource *DataSource `json:",omitempty"`

	// Custom is basically for extensibility and is not supposed to be used in OSS
	Custom interface{} `json:",omitempty"`
}

/****** Severity ******/

type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var (
	SeverityNames = []string{
		"UNKNOWN",
		"LOW",
		"MEDIUM",
		"HIGH",
		"CRITICAL",
	}
)

func NewSeverity(severity string) (Severity, error) {
	for i, name := range SeverityNames {
		if severity == name {
			return Severity(i), nil
		}
	}
	return SeverityUnknown, fmt.Errorf("unknown severity: %s", severity)
}

func CompareSeverityString(sev1, sev2 string) int {
	s1, _ := NewSeverity(sev1)
	s2, _ := NewSeverity(sev2)
	return int(s2) - int(s1)
}

func (s Severity) String() string {
	return SeverityNames[s]
}

/****** Status ******/

type Status int

const (
	StatusUnknown Status = iota
	StatusNotAffected
	StatusAffected
	StatusFixed
	StatusUnderInvestigation
	StatusWillNotFix // Red Hat specific
	StatusFixDeferred
	StatusEndOfLife
)

var (
	// Statuses is a list of statuses.
	// VEX has 4 statuses: not-affected, affected, fixed, and under_investigation.
	// cf. https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf
	//
	// In addition to them, Red Hat has "will_not_fix" and "fix_deferred".
	// cf. https://access.redhat.com/blogs/product-security/posts/2066793
	Statuses = []string{
		"unknown",
		"not_affected",
		"affected",
		"fixed",
		"under_investigation",
		"will_not_fix",
		"fix_deferred",
		"end_of_life",
	}
)

func NewStatus(status string) Status {
	for i, s := range Statuses {
		if status == s {
			return Status(i)
		}
	}
	return StatusUnknown
}

func (s *Status) String() string {
	idx := s.Index()
	if idx < 0 || idx >= len(Statuses) {
		idx = 0 // unknown
	}
	return Statuses[idx]
}

func (s *Status) Index() int {
	return int(*s)
}

func (s Status) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Status) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	*s = NewStatus(str)
	return nil
}

/****** Relationship ******/

type Relationship int

const (
	RelationshipUnknown Relationship = iota
	RelationshipRoot
	RelationshipWorkspace // For maven `modules`. TODO use it for cargo and npm workspaces
	RelationshipDirect
	RelationshipIndirect
)

var (
	Relationships = []Relationship{
		RelationshipUnknown,
		RelationshipRoot,
		RelationshipWorkspace,
		RelationshipDirect,
		RelationshipIndirect,
	}

	relationshipNames = [...]string{
		"unknown",
		"root",
		"workspace",
		"direct",
		"indirect",
	}
)

func NewRelationship(s string) (Relationship, error) {
	for i, name := range relationshipNames {
		if s == name {
			return Relationship(i), nil
		}
	}
	return RelationshipUnknown, xerrors.Errorf("invalid relationship (%s)", s)
}

func (r Relationship) String() string {
	if r <= RelationshipUnknown || int(r) >= len(relationshipNames) {
		return "unknown"
	}
	return relationshipNames[r]
}

func (r Relationship) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func (r *Relationship) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	for i, name := range relationshipNames {
		if s == name {
			*r = Relationship(i)
			return nil
		}
	}
	return xerrors.Errorf("invalid relationship (%s)", s)
}

/******** MISCONFIGURATIONS *******/

// DetectedMisconfiguration holds detected misconfigurations
type DetectedMisconfiguration struct {
	Type          string        `json:",omitempty"`
	ID            string        `json:",omitempty"`
	AVDID         string        `json:",omitempty"`
	Title         string        `json:",omitempty"`
	Description   string        `json:",omitempty"`
	Message       string        `json:",omitempty"`
	Namespace     string        `json:",omitempty"`
	Query         string        `json:",omitempty"`
	Resolution    string        `json:",omitempty"`
	Severity      string        `json:",omitempty"`
	PrimaryURL    string        `json:",omitempty"`
	References    []string      `json:",omitempty"`
	Status        MisconfStatus `json:",omitempty"`
	Layer         Layer         `json:",omitempty"`
	CauseMetadata CauseMetadata `json:",omitempty"`

	// For debugging
	Traces []string `json:",omitempty"`
}

// MisconfStatus represents a status of misconfiguration
type MisconfStatus string

const (
	// MisconfStatusPassed represents successful status
	MisconfStatusPassed MisconfStatus = "PASS"

	// MisconfStatusFailure represents failure status
	MisconfStatusFailure MisconfStatus = "FAIL"

	// MisconfStatusException Passed represents the status of exception
	MisconfStatusException MisconfStatus = "EXCEPTION"
)

func (DetectedMisconfiguration) findingType() FindingType { return FindingTypeMisconfiguration }

/************* FIndingType **********/

type FindingType string
type FindingStatus string

const (
	FindingTypeVulnerability    FindingType = "vulnerability"
	FindingTypeMisconfiguration FindingType = "misconfiguration"
	FindingTypeSecret           FindingType = "secret"
	FindingTypeLicense          FindingType = "license"

	FindingStatusIgnored            FindingStatus = "ignored"             // Trivy
	FindingStatusUnknown            FindingStatus = "unknown"             // Trivy
	FindingStatusNotAffected        FindingStatus = "not_affected"        // VEX
	FindingStatusAffected           FindingStatus = "affected"            // VEX
	FindingStatusFixed              FindingStatus = "fixed"               // VEX
	FindingStatusUnderInvestigation FindingStatus = "under_investigation" // VEX
)

// Finding represents one of the findings that Trivy can detect,
// such as vulnerabilities, misconfigurations, secrets, and licenses.
type finding interface {
	findingType() FindingType
}

// ModifiedFinding represents a security finding that has been modified by an external source,
// such as .trivyignore and VEX. Currently, it is primarily used to account for vulnerabilities
// that are ignored via .trivyignore or identified as not impactful through VEX.
// However, it is planned to also store vulnerabilities whose severity has been adjusted by VEX,
// or that have been detected through Wasm modules in the future.
type ModifiedFinding struct {
	Type      FindingType
	Status    FindingStatus
	Statement string
	Source    string
	Finding   finding // one of findings
}

func NewModifiedFinding(f finding, status FindingStatus, statement, source string) ModifiedFinding {
	return ModifiedFinding{
		Type:      f.findingType(),
		Status:    status,
		Statement: statement,
		Source:    source,
		Finding:   f,
	}
}

func (DetectedVulnerability) findingType() FindingType { return FindingTypeVulnerability }

// UnmarshalJSON unmarshals ModifiedFinding given the type and `UnmarshalJSON` functions of struct fields
func (m *ModifiedFinding) UnmarshalJSON(data []byte) error {
	type Alias ModifiedFinding
	aux := &struct {
		Finding json.RawMessage `json:"Finding"`
		*Alias
	}{
		Alias: (*Alias)(m),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Select struct by m.Type to avoid errors with Unmarshal
	var err error
	switch m.Type {
	case FindingTypeVulnerability:
		m.Finding, err = unmarshalFinding[DetectedVulnerability](aux.Finding)
	case FindingTypeMisconfiguration:
		m.Finding, err = unmarshalFinding[DetectedMisconfiguration](aux.Finding)
	case FindingTypeSecret:
		m.Finding, err = unmarshalFinding[DetectedSecret](aux.Finding)
	case FindingTypeLicense:
		m.Finding, err = unmarshalFinding[DetectedLicense](aux.Finding)
	default:
		return xerrors.Errorf("invalid Finding type: %s", m.Type)
	}

	if err != nil {
		return xerrors.Errorf("unable to unmarshal %q type: %w", m.Type, err)
	}
	return nil
}

func unmarshalFinding[T finding](data []byte) (T, error) {
	var f T
	err := json.Unmarshal(data, &f)
	return f, err
}

// ArtifactType represents a type of artifact
type ArtifactType string

const (
	TypeContainerImage ArtifactType = "container_image"
	TypeFilesystem     ArtifactType = "filesystem"
	TypeRepository     ArtifactType = "repository"
	TypeCycloneDX      ArtifactType = "cyclonedx"
	TypeSPDX           ArtifactType = "spdx"
	TypeAWSAccount     ArtifactType = "aws_account"
	TypeVM             ArtifactType = "vm"
)

type OS struct {
	Family db_langTypes.OSType
	Name   string
	Eosl   bool `json:"EOSL,omitempty"`

	// This field is used for enhanced security maintenance programs such as Ubuntu ESM, Debian Extended LTS.
	Extended bool `json:"extended,omitempty"`
}

func (o *OS) String() string {
	s := string(o.Family)
	if o.Name != "" {
		s += "/" + o.Name
	}
	return s
}

func (o *OS) Detected() bool {
	return o.Family != ""
}

// Normalize normalizes OS family names for backward compatibility
func (o *OS) Normalize() {
	if alias, ok := db_langTypes.OSTypeAliases[o.Family]; ok {
		o.Family = alias
	}
}

// Merge merges OS version and enhanced security maintenance programs
func (o *OS) Merge(newOS OS) {
	if lo.IsEmpty(newOS) {
		return
	}

	switch {
	// OLE also has /etc/redhat-release and it detects OLE as RHEL by mistake.
	// In that case, OS must be overwritten with the content of /etc/oracle-release.
	// There is the same problem between Debian and Ubuntu.
	case o.Family == db_langTypes.RedHat, o.Family == db_langTypes.Debian:
		*o = newOS
	default:
		if o.Family == "" {
			o.Family = newOS.Family
		}
		if o.Name == "" {
			o.Name = newOS.Name
		}
		// Ubuntu has ESM program: https://ubuntu.com/security/esm
		// OS version and esm status are stored in different files.
		// We have to merge OS version after parsing these files.
		if o.Extended || newOS.Extended {
			o.Extended = true
		}
	}
	// When merging layers, there are cases when a layer contains an OS with an old name:
	//   - Cache contains a layer derived from an old version of Trivy.
	//   - `client` uses an old version of Trivy, but `server` is a new version of Trivy (for `client/server` mode).
	// So we need to normalize the OS name for backward compatibility.
	o.Normalize()
}

type Repository struct {
	Family  db_langTypes.OSType `json:",omitempty"`
	Release string              `json:",omitempty"`
}

type Layer struct {
	Digest    string `json:",omitempty"`
	DiffID    string `json:",omitempty"`
	CreatedBy string `json:",omitempty"`
}

type PackageInfo struct {
	FilePath string
	Packages Packages
}

type Application struct {
	// e.g. bundler and pipenv
	Type db_langTypes.LangType

	// Lock files have the file path here, while each package metadata do not have
	FilePath string `json:",omitempty"`

	// Packages is a list of lang-specific packages
	Packages Packages
}

type Applications []Application

type File struct {
	Type    string
	Path    string
	Content []byte
}

// ArtifactInfo is stored in cache
type ArtifactInfo struct {
	SchemaVersion int
	Architecture  string
	Created       time.Time
	DockerVersion string
	OS            string

	// Misconfiguration holds misconfiguration in container image config
	Misconfiguration *Misconfiguration `json:",omitempty"`

	// Secret holds secrets in container image config such as environment variables
	Secret *Secret `json:",omitempty"`

	// HistoryPackages are packages extracted from RUN instructions
	HistoryPackages Packages `json:",omitempty"`
}

// BlobInfo is stored in cache
type BlobInfo struct {
	SchemaVersion int

	// Layer information
	Digest        string   `json:",omitempty"`
	DiffID        string   `json:",omitempty"`
	CreatedBy     string   `json:",omitempty"`
	OpaqueDirs    []string `json:",omitempty"`
	WhiteoutFiles []string `json:",omitempty"`

	// Analysis result
	OS                OS                 `json:",omitempty"`
	Repository        *Repository        `json:",omitempty"`
	PackageInfos      []PackageInfo      `json:",omitempty"`
	Applications      []Application      `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Secrets           []Secret           `json:",omitempty"`
	Licenses          []LicenseFile      `json:",omitempty"`

	// Red Hat distributions have build info per layer.
	// This information will be embedded into packages when applying layers.
	// ref. https://redhat-connect.gitbook.io/partner-guide-for-adopting-red-hat-oval-v2/determining-common-platform-enumeration-cpe
	BuildInfo *BuildInfo `json:",omitempty"`

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []CustomResource `json:",omitempty"`
}

// ArtifactDetail represents the analysis result.
type ArtifactDetail struct {
	OS                OS                 `json:",omitempty"`
	Repository        *Repository        `json:",omitempty"`
	Packages          Packages           `json:",omitempty"`
	Applications      Applications       `json:",omitempty"`
	Misconfigurations []Misconfiguration `json:",omitempty"`
	Secrets           Secrets            `json:",omitempty"`
	Licenses          LicenseFiles       `json:",omitempty"`

	// ImageConfig has information from container image config
	ImageConfig ImageConfigDetail

	// CustomResources hold analysis results from custom analyzers.
	// It is for extensibility and not used in OSS.
	CustomResources []CustomResource `json:",omitempty"`
}

// Sort sorts packages and applications in ArtifactDetail
func (a *ArtifactDetail) Sort() {
	sort.Sort(a.Packages)
	sort.Sort(a.Applications)
	sort.Sort(a.Secrets)
	sort.Sort(a.Licenses)
	// Misconfigurations will be sorted later
}

type Secrets []Secret

func (s Secrets) Len() int {
	return len(s)
}

func (s Secrets) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s Secrets) Less(i, j int) bool {
	return s[i].FilePath < s[j].FilePath
}

type LicenseType string

const (
	LicenseTypeDpkg   LicenseType = "dpkg"         // From /usr/share/doc/*/copyright
	LicenseTypeHeader LicenseType = "header"       // From file headers
	LicenseTypeFile   LicenseType = "license-file" // From LICENSE, COPYRIGHT, etc.
)

type LicenseFile struct {
	Type     LicenseType
	FilePath string
	PkgName  string
	Findings LicenseFindings
	Layer    Layer `json:",omitempty"`
}

type LicenseFindings []LicenseFinding

func (findings LicenseFindings) Len() int {
	return len(findings)
}

func (findings LicenseFindings) Swap(i, j int) {
	findings[i], findings[j] = findings[j], findings[i]
}

func (findings LicenseFindings) Less(i, j int) bool {
	return findings[i].Name < findings[j].Name
}

func (findings LicenseFindings) Names() []string {
	return lo.Map(findings, func(finding LicenseFinding, _ int) string {
		return finding.Name
	})
}

type LicenseFinding struct {
	Category   LicenseCategory // such as "forbidden"
	Name       string
	Confidence float64
	Link       string
}

type LicenseFiles []LicenseFile

func (l LicenseFiles) Len() int {
	return len(l)
}

func (l LicenseFiles) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func (l LicenseFiles) Less(i, j int) bool {
	switch {
	case l[i].Type != l[j].Type:
		return l[i].Type < l[j].Type
	default:
		return l[i].FilePath < l[j].FilePath
	}
}

// ImageConfigDetail has information from container image config
type ImageConfigDetail struct {
	// Packages are packages extracted from RUN instructions in history
	Packages []Package `json:",omitempty"`

	// Misconfiguration holds misconfigurations in container image config
	Misconfiguration *Misconfiguration `json:",omitempty"`

	// Secret holds secrets in container image config
	Secret *Secret `json:",omitempty"`
}

const (
	ArtifactJSONSchemaVersion = 1
	BlobJSONSchemaVersion     = 2
)

// ToBlobInfo is used to store a merged layer in cache.
func (a *ArtifactDetail) ToBlobInfo() BlobInfo {
	return BlobInfo{
		SchemaVersion: BlobJSONSchemaVersion,
		OS:            a.OS,
		Repository:    a.Repository,
		PackageInfos: []PackageInfo{
			{
				FilePath: "merged", // Set a dummy file path
				Packages: a.Packages,
			},
		},
		Applications:      a.Applications,
		Misconfigurations: a.Misconfigurations,
		Secrets:           a.Secrets,
		Licenses:          a.Licenses,
		CustomResources:   a.CustomResources,
	}
}

type Misconfiguration struct {
	FileType  db_langTypes.ConfigType `json:",omitempty"`
	FilePath  string                  `json:",omitempty"`
	Successes MisconfResults          `json:",omitempty"`
	Warnings  MisconfResults          `json:",omitempty"`
	Failures  MisconfResults          `json:",omitempty"`
	Layer     Layer                   `json:",omitempty"`
}

type MisconfResult struct {
	Namespace      string `json:",omitempty"`
	Query          string `json:",omitempty"`
	Message        string `json:",omitempty"`
	PolicyMetadata `json:",omitempty"`
	CauseMetadata  `json:",omitempty"`

	// For debugging
	Traces []string `json:",omitempty"`
}

type MisconfResults []MisconfResult

type PolicyMetadata struct {
	ID                 string   `json:",omitempty"`
	AVDID              string   `json:",omitempty"`
	Type               string   `json:",omitempty"`
	Title              string   `json:",omitempty"`
	Description        string   `json:",omitempty"`
	Severity           string   `json:",omitempty"`
	RecommendedActions string   `json:",omitempty" mapstructure:"recommended_actions"`
	References         []string `json:",omitempty"`
}

type PolicyInputOption struct {
	Combine   bool                  `mapstructure:"combine"`
	Selectors []PolicyInputSelector `mapstructure:"selector"`
}

type PolicyInputSelector struct {
	Type string `mapstructure:"type"`
}

func (r MisconfResults) Len() int {
	return len(r)
}

func (r MisconfResults) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

func (r MisconfResults) Less(i, j int) bool {
	switch {
	case r[i].Type != r[j].Type:
		return r[i].Type < r[j].Type
	case r[i].AVDID != r[j].AVDID:
		return r[i].AVDID < r[j].AVDID
	case r[i].ID != r[j].ID:
		return r[i].ID < r[j].ID
	case r[i].Severity != r[j].Severity:
		return r[i].Severity < r[j].Severity
	case r[i].Resource != r[j].Resource:
		return r[i].Resource < r[j].Resource
	}
	return r[i].Message < r[j].Message
}

func ToMisconfigurations(misconfs map[string]Misconfiguration) []Misconfiguration {
	var results []Misconfiguration
	for _, misconf := range misconfs {
		// Remove duplicates
		misconf.Successes = uniqueResults(misconf.Successes)
		misconf.Warnings = uniqueResults(misconf.Warnings)
		misconf.Failures = uniqueResults(misconf.Failures)

		// Sort results
		sort.Sort(misconf.Successes)
		sort.Sort(misconf.Warnings)
		sort.Sort(misconf.Failures)

		results = append(results, misconf)
	}

	// Sort misconfigurations
	sort.Slice(results, func(i, j int) bool {
		if results[i].FileType != results[j].FileType {
			return results[i].FileType < results[j].FileType
		}
		return results[i].FilePath < results[j].FilePath
	})

	return results
}

func uniqueResults(results []MisconfResult) []MisconfResult {
	if len(results) == 0 {
		return results
	}
	return lo.UniqBy(results, func(result MisconfResult) string {
		return fmt.Sprintf("ID: %s, Namespace: %s, Messsage: %s, Cause: %v",
			result.ID, result.Namespace, result.Message, result.CauseMetadata)
	})
}
