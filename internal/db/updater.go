package db

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Metadata holds information about the DB update.
type Metadata struct {
	Version      int       `json:"Version"`
	NextUpdate   time.Time `json:"NextUpdate"`
	UpdatedAt    time.Time `json:"UpdatedAt"`
	DownloadedAt time.Time `json:"DownloadedAt"`
}

// dbExists checks if the DB file exists.
func dbExists(dir string) bool {
	dbPath := filepath.Join(dir, DBFilename)
	_, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		log.Printf("[INFO] DB file %s does not exist.", dbPath)
		return false
	}
	log.Printf("[INFO] DB file %s exists.", dbPath)
	return true
}

// metadataExists checks if the metadata file exists.
func metadataExists(dir string) bool {
	metaPath := filepath.Join(dir, MetadataFilename)
	_, err := os.Stat(metaPath)
	if os.IsNotExist(err) {
		log.Printf("[INFO] Metadata file %s does not exist.", metaPath)
		return false
	}
	log.Printf("[INFO] Metadata file %s exists.", metaPath)
	return true
}

// readMetadata reads and unmarshals the metadata file.
func readMetadata(dir string) (*Metadata, error) {
	metaPath := filepath.Join(dir, MetadataFilename)
	log.Printf("[DEBUG] Reading metadata from %s", metaPath)
	f, err := os.Open(metaPath)
	if err != nil {
		log.Printf("[ERROR] Failed to open metadata file %s: %v", metaPath, err)
		return nil, err
	}
	defer f.Close()

	var meta Metadata
	if err := json.NewDecoder(f).Decode(&meta); err != nil {
		log.Printf("[ERROR] Failed to decode metadata from %s: %v", metaPath, err)
		return nil, err
	}
	log.Printf("[INFO] Successfully read metadata: %+v", meta)
	return &meta, nil
}

// needsUpdate returns true if the current time is after meta.NextUpdate.
func needsUpdate(meta *Metadata) bool {
	if time.Now().After(meta.NextUpdate) {
		log.Printf("[INFO] Current time is past NextUpdate (%s). Update needed.", meta.NextUpdate)
		return true
	}
	log.Printf("[INFO] Current time is before NextUpdate (%s). No update needed.", meta.NextUpdate)
	return false
}

// writeMetadata writes the metadata to the file.
func writeMetadata(dir string, meta *Metadata) error {
	metaPath := filepath.Join(dir, MetadataFilename)
	log.Printf("[DEBUG] Writing metadata to %s", metaPath)
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		log.Printf("[ERROR] Failed to marshal metadata: %v", err)
		return err
	}
	if err := os.WriteFile(metaPath, data, 0644); err != nil {
		log.Printf("[ERROR] Failed to write metadata file %s: %v", metaPath, err)
		return err
	}
	log.Printf("[INFO] Metadata successfully written: %+v", meta)
	return nil
}

// extractAndRename extracts a .tar.gz file and renames the first regular file to bugs.db.
func extractAndRename(tarGzPath, destDir string) error {
	log.Printf("[DEBUG] Extracting tar.gz file %s into directory %s", tarGzPath, destDir)
	f, err := os.Open(tarGzPath)
	if err != nil {
		log.Printf("[ERROR] Failed to open tar.gz file %s: %v", tarGzPath, err)
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		log.Printf("[ERROR] Failed to create gzip reader for %s: %v", tarGzPath, err)
		return err
	}
	defer gz.Close()

	tarReader := tar.NewReader(gz)
	// Look for the first regular file in the archive.
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			log.Printf("[ERROR] Error reading tar archive %s: %v", tarGzPath, err)
			return err
		}
		if hdr.Typeflag == tar.TypeReg {
			outPath := filepath.Join(destDir, DBFilename)
			if err := os.MkdirAll(destDir, 0755); err != nil {
				log.Printf("[ERROR] Failed to create destination directory %s: %v", destDir, err)
				return err
			}
			outFile, err := os.Create(outPath)
			if err != nil {
				log.Printf("[ERROR] Failed to create file %s: %v", outPath, err)
				return err
			}
			log.Printf("[INFO] Extracting file %s to %s", hdr.Name, outPath)
			_, err = io.Copy(outFile, tarReader)
			outFile.Close()
			if err != nil {
				log.Printf("[ERROR] Error copying data to %s: %v", outPath, err)
				return err
			}
			log.Printf("[INFO] Extraction complete. DB renamed to %s", outPath)
			return nil
		}
	}
	err = fmt.Errorf("no regular file found in archive %s", tarGzPath)
	log.Printf("[ERROR] %v", err)
	return err
}

// downloadDBFromRepo attempts to download, extract, and update metadata from a single repository.
func downloadDBFromRepo(ctx context.Context, destDir, repo string) error {
	log.Printf("[INFO] Attempting to download DB from repository: %s", repo)
	ref, err := name.ParseReference(repo)
	if err != nil {
		errMsg := fmt.Errorf("error parsing repository %s: %w", repo, err)
		log.Printf("[ERROR] %v", errMsg)
		return errMsg
	}
	img, err := remote.Image(ref)
	if err != nil {
		errMsg := fmt.Errorf("error fetching image from %s: %w", repo, err)
		log.Printf("[ERROR] %v", errMsg)
		return errMsg
	}
	layers, err := img.Layers()
	if err != nil {
		errMsg := fmt.Errorf("error getting layers from %s: %w", repo, err)
		log.Printf("[ERROR] %v", errMsg)
		return errMsg
	}
	if len(layers) != 1 {
		errMsg := fmt.Errorf("expected single layer in %s, got %d", repo, len(layers))
		log.Printf("[ERROR] %v", errMsg)
		return errMsg
	}
	layer := layers[0]
	rc, err := layer.Compressed()
	if err != nil {
		errMsg := fmt.Errorf("error fetching compressed layer from %s: %w", repo, err)
		log.Printf("[ERROR] %v", errMsg)
		return errMsg
	}
	defer rc.Close()

	// Write the layer to a temporary tar.gz file.
	tmpFile, err := os.CreateTemp("", "trivy-db-*.tar.gz")
	if err != nil {
		errMsg := fmt.Errorf("error creating temp file: %w", err)
		log.Printf("[ERROR] %v", errMsg)
		return errMsg
	}
	tmpPath := tmpFile.Name()
	log.Printf("[DEBUG] Writing OCI layer data to temporary file %s", tmpPath)
	if _, err := io.Copy(tmpFile, rc); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		errMsg := fmt.Errorf("error writing to temp file %s: %w", tmpPath, err)
		log.Printf("[ERROR] %v", errMsg)
		return errMsg
	}
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// Extract the tar.gz archive and rename the file to bugs.db.
	if err := extractAndRename(tmpPath, destDir); err != nil {
		errMsg := fmt.Errorf("error extracting and renaming file from %s: %w", repo, err)
		log.Printf("[ERROR] %v", errMsg)
		return errMsg
	}

	// Update metadata: here we hardcode version=2 and set NextUpdate 24 hours later.
	now := time.Now().UTC()
	meta := &Metadata{
		Version:      2,
		UpdatedAt:    now,
		DownloadedAt: now,
		NextUpdate:   now.Add(24 * time.Hour),
	}
	if err := writeMetadata(destDir, meta); err != nil {
		errMsg := fmt.Errorf("error writing metadata from %s: %w", repo, err)
		log.Printf("[ERROR] %v", errMsg)
		return errMsg
	}

	log.Printf("[INFO] Successfully downloaded and updated DB from repository: %s", repo)
	return nil
}

// downloadDB tries each repository in order until one download succeeds.
func downloadDB(ctx context.Context, destDir string, repos []string) error {
	var lastErr error
	for _, repo := range repos {
		log.Printf("[INFO] Trying repository: %s", repo)
		if err := downloadDBFromRepo(ctx, destDir, repo); err != nil {
			lastErr = err
			log.Printf("[WARN] Download from repository %s failed with error: %v", repo, err)
			continue
		}
		// Successful download.
		return nil
	}
	log.Printf("[ERROR] All repository attempts failed. Last error: %v", lastErr)
	return lastErr
}

// updateDBIfNeeded checks if the DB or metadata exists and whether an update is needed.
// It then downloads/updates the DB and metadata accordingly.
func UpdateDBIfNeeded(ctx context.Context, destDir string, repos []string) error {
	log.Printf("[INFO] Starting DB update check in directory: %s", destDir)
	if !dbExists(destDir) || !metadataExists(destDir) {
		log.Println("[INFO] Either DB or metadata does not exist. Initiating DB download...")
		return downloadDB(ctx, destDir, repos)
	}

	meta, err := readMetadata(destDir)
	if err != nil {
		log.Printf("[WARN] Failed to read metadata: %v. Initiating DB download...", err)
		return downloadDB(ctx, destDir, repos)
	}

	if needsUpdate(meta) {
		log.Println("[INFO] DB update required. Initiating DB download...")
		return downloadDB(ctx, destDir, repos)
	}

	log.Println("[INFO] DB and metadata are up-to-date; no update needed.")
	return nil
}
