package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"vulndetector/internal/db"
	detect_vuln "vulndetector/internal/detect"

	db_langTypes "vulndetector/internal/db/langTypes"
	db_types "vulndetector/internal/db/types"

	set "vulndetector/internal/set"

	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

var (
	PkgTargets = map[db_langTypes.LangType]string{
		db_langTypes.PythonPkg:   "Python",
		db_langTypes.CondaPkg:    "Conda",
		db_langTypes.GemSpec:     "Ruby",
		db_langTypes.NodePkg:     "Node.js",
		db_langTypes.Jar:         "Java",
		db_langTypes.K8sUpstream: "Kubernetes",
	}
)

// Scan iterates over applications, sorts packages, scans for vulnerabilities,
// and returns a list of results.
func Scan(ctx context.Context, database db.DB, apps db_types.Applications, targetLanguage string) (db_types.Results, error) {
	if len(apps) == 0 {
		return nil, nil
	}

	var results db_types.Results
	printedTypes := set.New[db_langTypes.LangType]()

	for _, app := range apps {
		if len(app.Packages) == 0 {
			continue
		}

		// Prepare a result for the application.
		result := db_types.Result{
			Target: getTargetName(app.Type, app.FilePath),
			Class:  db_types.ClassLangPkg,
			Type:   app.Type,
		}

		// Sort packages before scanning.
		sort.Sort(app.Packages)
		result.Packages = app.Packages

		// Scan for vulnerabilities in the application's packages.
		vulns, err := scanAppVulnerabilities(ctx, database, app, printedTypes)
		if err != nil {
			return nil, err
		}
		result.Vulnerabilities = vulns

		// Append result only if there are packages or vulnerabilities.
		if len(result.Packages) > 0 || len(result.Vulnerabilities) > 0 {
			results = append(results, result)
		}
	}

	// Sort results alphabetically by target.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results, nil
}

// scanAppVulnerabilities logs detection once per language type and scans packages.
func scanAppVulnerabilities(ctx context.Context, database db.DB, app db_types.Application, printedTypes set.Set[db_langTypes.LangType]) ([]db_types.DetectedVulnerability, error) {
	if !printedTypes.Contains(app.Type) {
		// Log once per language type.
		// log.InfoContext(ctx, "Detecting vulnerabilities for", log.String("type", string(app.Type)))
		printedTypes.Append(app.Type)
	}
	return detect(ctx, database, app.Type, app.Packages)
}

// Detect iterates through packages and retrieves vulnerabilities for each package.
func detect(ctx context.Context, database db.DB, libType db_langTypes.LangType, pkgs []db_types.Package) ([]db_types.DetectedVulnerability, error) {
	var vulnerabilities []db_types.DetectedVulnerability

	for _, pkg := range pkgs {
		if pkg.Version == "" {
			// Skip packages with no version.
			continue
		}

		// Scan for vulnerabilities using the language type.
		vulns, err := detectVulnerabilities(database, pkg.ID, pkg.Name, pkg.Version, string(libType))
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", string(libType), err)
		}

		// Enrich each vulnerability with package details.
		for i := range vulns {
			vulns[i].Layer = pkg.Layer
			vulns[i].PkgPath = pkg.FilePath
			vulns[i].PkgIdentifier = pkg.Identifier
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

// DetectVulnerabilities retrieves advisories from the database and checks if the package version is vulnerable.
func detectVulnerabilities(database db.DB, pkgID, pkgName, pkgVer string, ecosystem string) ([]db_types.DetectedVulnerability, error) {
	// Construct a prefix like "pip::" or "npm::"
	prefix := fmt.Sprintf("%s::", ecosystem)
	normalizedPkgName := detect_vuln.NormalizePkgName(db_types.Ecosystem(ecosystem), pkgName)
	advisories, err := database.GetAdvisoriesForSource(prefix, normalizedPkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", ecosystem, err)
	}

	var vulns []db_types.DetectedVulnerability
	for _, adv := range advisories {
		// If the package version is not vulnerable, skip this advisory.
		if !d.comparer.IsVulnerable(pkgVer, adv) {
			continue
		}

		vuln := db_types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			PkgID:            pkgID,
			PkgName:          pkgName,
			InstalledVersion: pkgVer,
			FixedVersion:     createFixedVersions(adv),
			DataSource:       adv.DataSource,
			Custom:           adv.Custom,
		}
		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// getTargetName returns a default target name based on the package type if the file path is empty.
func getTargetName(appType db_langTypes.LangType, filePath string) string {
	if name, ok := PkgTargets[appType]; ok && filePath == "" {
		return name
	}
	return filePath
}

// createFixedVersions constructs a fixed version string from an advisory.
// If patched versions exist, it uses those; otherwise, it derives fixed versions from the vulnerable versions.
func createFixedVersions(advisory db_types.Advisory) string {
	if len(advisory.PatchedVersions) != 0 {
		return joinFixedVersions(advisory.PatchedVersions)
	}

	var fixedVersions []string
	for _, version := range advisory.VulnerableVersions {
		for _, s := range strings.Split(version, ",") {
			s = strings.TrimSpace(s)
			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
				s = strings.TrimPrefix(s, "<")
				fixedVersions = append(fixedVersions, strings.TrimSpace(s))
			}
		}
	}
	return joinFixedVersions(fixedVersions)
}

// joinFixedVersions returns a comma-separated string of unique fixed versions.
func joinFixedVersions(fixedVersions []string) string {
	return strings.Join(lo.Uniq(fixedVersions), ", ")
}
