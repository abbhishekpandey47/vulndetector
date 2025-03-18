package scan

// import (
// 	"context"
// 	"fmt"
// 	"sort"
// 	"strings"
// 	"vulndetector/internal/db"
// 	detect_vuln "vulndetector/internal/detect"

// 	db_langTypes "vulndetector/internal/db/langTypes"
// 	db_types "vulndetector/internal/db/types"

// 	"github.com/samber/lo"
// 	"golang.org/x/xerrors"
// 	"k8s.io/utils/set"
// )

// // // Package represents a library extracted from your project.
// // type Package struct {
// // 	Name    string
// // 	Version string
// // }

// // // DetectedVulnerability represents a vulnerability found for a package.
// // type DetectedVulnerability struct {
// // 	VulnerabilityID  string
// // 	PackageName      string
// // 	InstalledVersion string
// // 	FixedVersion     string
// // 	DataSource       string
// // }

// // var (
// // 	PkgTargets = map[db_langTypes.LangType]string{
// // 		db_langTypes.PythonPkg:   "Python",
// // 		db_langTypes.CondaPkg:    "Conda",
// // 		db_langTypes.GemSpec:     "Ruby",
// // 		db_langTypes.NodePkg:     "Node.js",
// // 		db_langTypes.Jar:         "Java",
// // 		db_langTypes.K8sUpstream: "Kubernetes",
// // 	}
// // )

// func Scan(ctx context.Context, target db_types.Applications, targetLanguage string) (db_types.Results, error) {
// 	apps := target
// 	//log.Info("Number of language-specific files", log.Int("num", len(apps)))
// 	if len(apps) == 0 {
// 		return nil, nil
// 	}

// 	var results db_types.Results
// 	printedTypes := set.New[db_langTypes.LangType]()
// 	for _, app := range apps {
// 		if len(app.Packages) == 0 {
// 			continue
// 		}

// 		//ctx = log.WithContextPrefix(ctx, string(app.Type))
// 		result := db_types.Result{
// 			Target: targetName(app.Type, app.FilePath),
// 			Class:  db_types.ClassLangPkg,
// 			Type:   app.Type,
// 		}

// 		sort.Sort(app.Packages)
// 		result.Packages = app.Packages

// 		var err error
// 		result.Vulnerabilities, err = scanVulnerabilities(ctx, app, printedTypes)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if len(result.Packages) == 0 && len(result.Vulnerabilities) == 0 {
// 			continue
// 		}
// 		results = append(results, result)
// 	}
// 	sort.Slice(results, func(i, j int) bool {
// 		return results[i].Target < results[j].Target
// 	})
// 	return results, nil
// }

// func scanVulnerabilities(ctx context.Context, app db_types.Application, printedTypes set.Set[db_langTypes.LangType]) ([]db_types.DetectedVulnerability, error) {

// 	// Prevent the same log messages from being displayed many times for the same type.
// 	if !printedTypes.Contains(app.Type) {
// 		//log.InfoContext(ctx, "Detecting vulnerabilities...")
// 		printedTypes.Append(app.Type)
// 	}

// 	//log.DebugContext(ctx, "Scanning packages for vulnerabilities", log.FilePath(app.FilePath))
// 	vulns, err := Detect(ctx, app.Type, app.Packages)
// 	if err != nil {
// 		return nil, xerrors.Errorf("failed vulnerability detection of libraries: %w", err)
// 	}
// 	return vulns, err
// }

// // }

// func Detect(ctx context.Context, database db.DB, libType db_langTypes.LangType, pkgs []db_types.Package) ([]db_types.DetectedVulnerability, error) {
// 	var vulnerabilities []db_types.DetectedVulnerability

// 	// Loop through each package.
// 	for _, pkg := range pkgs {
// 		if pkg.Version == "" {
// 			// Skip packages with no version.
// 			continue
// 		}
// 		// Here, we use libType (converted to string) instead of the hard-coded "GO".
// 		vulns, err := DetectVulnerabilities(database, pkg.ID, pkg.Name, pkg.Version, string(libType))
// 		if err != nil {
// 			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", string(libType), err)
// 		}

// 		// Set package-specific fields for each detected vulnerability.
// 		for i := range vulns {
// 			vulns[i].Layer = pkg.Layer
// 			vulns[i].PkgPath = pkg.FilePath
// 			vulns[i].PkgIdentifier = pkg.Identifier
// 		}
// 		vulnerabilities = append(vulnerabilities, vulns...)
// 	}

// 	return vulnerabilities, nil
// }

// // DetectVulnerabilities scans buckets with the prefix according to the ecosystem.
// // If "ecosystem" is pip, it looks for buckets with "pip::" and gets security advisories from those buckets.
// // It allows us to add a new data source with the ecosystem prefix (e.g. pip::new-data-source)
// // and detect vulnerabilities without specifying a specific bucket name.
// func DetectVulnerabilities(database db.DB, pkgID, pkgName, pkgVer string, ecosystem string) ([]db_types.DetectedVulnerability, error) {
// 	// e.g. "pip::", "npm::"
// 	prefix := fmt.Sprintf("%s::", ecosystem)
// 	advisories, err := database.GetAdvisoriesForSource(prefix, detect_vuln.NormalizePkgName(ecosystem, pkgName))
// 	if err != nil {
// 		return nil, xerrors.Errorf("failed to get %s advisories: %w", ecosystem, err)
// 	}

// 	var vulns []db_types.DetectedVulnerability
// 	for _, adv := range advisories {
// 		if !d.comparer.IsVulnerable(pkgVer, adv) { // Todo Create comparer function to be used here
// 			continue
// 		}

// 		vuln := db_types.DetectedVulnerability{
// 			VulnerabilityID:  adv.VulnerabilityID,
// 			PkgID:            pkgID,
// 			PkgName:          pkgName,
// 			InstalledVersion: pkgVer,
// 			FixedVersion:     createFixedVersions(adv),
// 			DataSource:       adv.DataSource,
// 			Custom:           adv.Custom,
// 		}
// 		vulns = append(vulns, vuln)
// 	}

// 	return vulns, nil
// }

// func targetName(appType db_langTypes.LangType, filePath string) string {
// 	if t, ok := PkgTargets[appType]; ok && filePath == "" {
// 		// When the file path is empty, we will overwrite it with the pre-defined value.
// 		return t
// 	}
// 	return filePath
// }

// func createFixedVersions(advisory db_types.Advisory) string {
// 	if len(advisory.PatchedVersions) != 0 {
// 		return joinFixedVersions(advisory.PatchedVersions)
// 	}

// 	var fixedVersions []string
// 	for _, version := range advisory.VulnerableVersions {
// 		for _, s := range strings.Split(version, ",") {
// 			s = strings.TrimSpace(s)
// 			if !strings.HasPrefix(s, "<=") && strings.HasPrefix(s, "<") {
// 				s = strings.TrimPrefix(s, "<")
// 				fixedVersions = append(fixedVersions, strings.TrimSpace(s))
// 			}
// 		}
// 	}
// 	return joinFixedVersions(fixedVersions)
// }

// func joinFixedVersions(fixedVersions []string) string {
// 	return strings.Join(lo.Uniq(fixedVersions), ", ")
// }

// // Detect scans language-specific packages and returns vulnerabilities.
// // func Detect(ctx context.Context, database db.DB, libType db_langTypes.LangType, pkgs []db_types.Package) ([]db_types.DetectedVulnerability, error) {
// // 	// driver, ok := NewDriver(libType)
// // 	// if !ok {
// // 	// 	return nil, nil
// // 	// }

// // 	vulns, err := detect(ctx, database, libType, pkgs)
// // 	if err != nil {
// // 		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", driver.Type(), err)
// // 	}

// // 	return vulns, nil
// // }

// // func detect(ctx context.Context, database db.DB, libType db_langTypes.LangType, pkgs []db_types.Package) ([]db_types.DetectedVulnerability, error) {
// // 	var vulnerabilities []db_types.DetectedVulnerability
// // 	for _, pkg := range pkgs {
// // 		if pkg.Version == "" {
// // 			//log.DebugContext(ctx, "Skipping vulnerability scan as no version is detected for the package",
// // 			//log.String("name", pkg.Name))
// // 			continue
// // 		}
// // 		vulns, err := DetectVulnerabilities(database, pkg.ID, pkg.Name, pkg.Version, "GO") // Remove go from here
// // 		if err != nil {
// // 			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", driver.Type(), err)
// // 		}

// // 		for i := range vulns {
// // 			vulns[i].Layer = pkg.Layer
// // 			vulns[i].PkgPath = pkg.FilePath
// // 			vulns[i].PkgIdentifier = pkg.Identifier
// // 		}
// // 		vulnerabilities = append(vulnerabilities, vulns...)
// // 	}

// // 	return vulnerabilities, nil

// /*********** Existing Code *********/
// // ScanPackages iterates over a list of packages and checks them against advisories from the DB.
// // func ScanPackages(database db.DB, packages []Package) []DetectedVulnerability {
// // 	var results []DetectedVulnerability
// // 	comparer := compare.GenericComparer{}

// // 	advisories, err := database.GetAdvisories()
// // 	if err != nil {
// // 		// In a real application, log the error.
// // 		fmt.Println("Error Occured :", err.Error())
// // 		return results
// // 	}
// // 	for i, pkg := range packages {

// // 		if i == 1 {
// // 			fmt.Printf("--> PKGS : %+v", pkg)
// // 		}

// // 		for j, adv := range advisories {

// // 			if j == 1 {
// // 				fmt.Printf("--> ADVISORIES : %+v", adv)
// // 			}

// // 			if adv.PackageName == pkg.Name {
// // 				if comparer.IsVulnerable(pkg.Version, adv) {
// // 					results = append(results, DetectedVulnerability{
// // 						VulnerabilityID:  adv.VulnerabilityID,
// // 						PackageName:      adv.PackageName,
// // 						InstalledVersion: pkg.Version,
// // 						FixedVersion:     adv.FixedVersion,
// // 						DataSource:       adv.DataSource,
// // 					})
// // 				}
// // 			}
// // 		}
// // 	}
// // 	return results
// // }
