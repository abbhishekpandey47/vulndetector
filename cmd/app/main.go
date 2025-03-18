package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"

	db "vulndetector/internal/db"
	extract "vulndetector/internal/extract"
	scan "vulndetector/internal/scan"
)

func main() {
	ctx := context.Background()

	// Ensure the vulnerability DB is downloaded & up-to-date.
	if err := db.UpdateDBIfNeeded(ctx, db.DstDir, db.Repositories); err != nil {
		log.Fatalf("[FATAL] Error updating DB: %v", err)
	}
	log.Printf("[INFO] DB is ready at %s", filepath.Join(db.DstDir, db.DBFilename))

	// Open the Bolt DB using the correct path.
	database, err := db.NewDB()
	if err != nil {
		log.Fatalf("Failed to open Bolt DB: %v", err)
	}
	defer database.Close()

	// Simulated list of libraries extracted from go.mod/go.sum.
	// pkgs := []scan.Package{
	// 	{Name: "github.com/gin-gonic/gin", Version: "1.5.0"},
	// 	{Name: "github.com/sirupsen/logrus", Version: "1.7.0"},
	// 	{Name: "golang.org/x/crypto", Version: "0.0.0"},
	// }

	// Instead of a simulated list, extract the libraries from a given directory.
	// Replace "./your_project_dir" with the directory to search.

	list, err := database.ListAllBuckets()

	if err != nil {
		fmt.Println("Error occured ", err.Error())
	}
	for _, l := range list {
		fmt.Println("Bucket : ", l)
	}

	rootDir := "."
	pkgs, err := extract.ExtractPackages(rootDir)
	if err != nil {
		log.Fatalf("Error extracting packages: %v", err)
	}
	log.Printf("[INFO] Extracted %d packages from %s", len(pkgs), rootDir)

	// Scan the package list against the vulnerability database.
	vulnerabilities := scan.Scan(ctx, database, pkgs, "GO")
	if len(vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found.")
	} else {
		fmt.Println("Vulnerabilities found:")
		for _, v := range vulnerabilities {
			fmt.Printf("ID: %s, Package: %s, Installed: %s, Fixed: %s, Source: %s\n",
				v.VulnerabilityID, v.PackageName, v.InstalledVersion, v.FixedVersion, v.DataSource)
		}
	}
}
