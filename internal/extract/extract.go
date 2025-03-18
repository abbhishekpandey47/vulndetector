package extract

import (
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"

	scan "vulndetector/internal/scan"
)

// ExtractPackages walks the given root directory, finds all go.mod files,
// parses them, and returns a slice of packages (library name and version).
func ExtractPackages(root string) ([]scan.Package, error) {
	var packages []scan.Package

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// If there's an error accessing a file, return it.
			return err
		}
		// Look for go.mod files.
		if !info.IsDir() && info.Name() == "go.mod" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// Parse the go.mod file.
			modFile, err := modfile.Parse(path, data, nil)
			if err != nil {
				return err
			}
			// Iterate over require statements.
			for _, req := range modFile.Require {
				packages = append(packages, scan.Package{
					Name:    req.Mod.Path,
					Version: req.Mod.Version,
				})
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return packages, nil
}
