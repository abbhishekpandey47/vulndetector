package util

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

// ParserFunc defines the type for parser functions.
type ParserFunc func(filePaths []string)

// LanguageInfo holds language name, a list of file paths, and its parser.
type LanguageInfo struct {
	Language  string
	FilePaths []string
	Parser    ParserFunc
}

// Parser functions for different languages.
func javaParser(filePaths []string) {
	log.Println("Executing javaParser...")
	for _, path := range filePaths {
		log.Println("Parsing Java file:", path)
	}
}

func goParser(filePaths []string) {
	log.Println("Executing goParser...")
	for _, path := range filePaths {
		log.Println("Parsing Go file:", path)
	}
}

func pythonParser(filePaths []string) {
	log.Println("Executing pythonParser...")
	for _, path := range filePaths {
		log.Println("Parsing Python file:", path)
	}
}

func cParser(filePaths []string) {
	log.Println("Executing cParser...")
	for _, path := range filePaths {
		log.Println("Parsing C file:", path)
	}
}

// getLanguage returns the language name and corresponding parser based on file extension.
func getLanguage(fileName string) (string, ParserFunc) {
	ext := strings.ToLower(filepath.Ext(fileName))
	switch ext {
	case ".java":
		return "java", javaParser
	case ".go":
		return "go", goParser
	case ".py":
		return "python", pythonParser
	case ".c":
		return "c", cParser
	default:
		return "", nil
	}
}

// traverseDirectory walks through the directory and updates the languages map.
func traverseDirectory(root string, languages map[string]*LanguageInfo) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("Error accessing %q: %v\n", path, err)
			return err
		}
		// Skip directories, but log their visit.
		if info.IsDir() {
			log.Printf("Visiting directory: %s\n", path)
			return nil
		}
		lang, parser := getLanguage(info.Name())
		if lang == "" {
			// Skip files with unsupported extensions.
			log.Printf("Skipping file (unsupported extension): %s\n", path)
			return nil
		}
		log.Printf("Found %s file: %s\n", lang, path)
		// If the language is not already in the map, add it.
		if _, exists := languages[lang]; !exists {
			languages[lang] = &LanguageInfo{
				Language:  lang,
				FilePaths: []string{},
				Parser:    parser,
			}
		}
		// Append the file path.
		languages[lang].FilePaths = append(languages[lang].FilePaths, path)
		return nil
	})
}

// func main() {
// 	// Validate command-line argument for directory input.
// 	if len(os.Args) < 2 {
// 		log.Fatalf("Usage: %s <directory_path>\n", os.Args[0])
// 	}
// 	root := os.Args[1]

// 	// Create a map to hold language information.
// 	languages := make(map[string]*LanguageInfo)

// 	// Traverse the file system starting at the root directory.
// 	log.Printf("Starting directory traversal at: %s\n", root)
// 	err := traverseDirectory(root, languages)
// 	if err != nil {
// 		log.Fatalf("Error during directory traversal: %v", err)
// 	}

// 	// Output the collected file paths and execute each parser.
// 	for lang, info := range languages {
// 		log.Printf("Language: %s, Files: %v\n", lang, info.FilePaths)
// 		if info.Parser != nil {
// 			info.Parser(info.FilePaths)
// 		}
// 	}
// }
