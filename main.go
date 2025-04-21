package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"flag"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/jzelinskie/whirlpool"
	"github.com/mikhirev/gostribog"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"gopkg.in/yaml.v3"
)

var hasherMap = map[string]func() (hashPair, error){
	"blake2b": func() (hashPair, error) {
		h, _ := blake2b.New512(nil)
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"blake2s": func() (hashPair, error) {
		h, _ := blake2s.New256(nil)
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"blake3": func() (hashPair, error) {
		h := blake3.New()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha256": func() (hashPair, error) {
		h := sha256.New()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha512": func() (hashPair, error) {
		h := sha512.New()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"streebog256": func() (hashPair, error) {
		h := gostribog.New256()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"streebog512": func() (hashPair, error) {
		h := gostribog.New512()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"whirlpool": func() (hashPair, error) {
		h := whirlpool.New()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"md4": func() (hashPair, error) {
		h := md4.New()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha3-224": func() (hashPair, error) {
		h := sha3.New224()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha3-256": func() (hashPair, error) {
		h := sha3.New256()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha3-384": func() (hashPair, error) {
		h := sha3.New384()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha3-512": func() (hashPair, error) {
		h := sha3.New512()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"crc32_IEEE": func() (hashPair, error) {
		h := crc32.NewIEEE()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"crc32_Castagnoli": func() (hashPair, error) {
		h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"crc32_Koopman": func() (hashPair, error) {
		h := crc32.New(crc32.MakeTable(crc32.Koopman))
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"crc64_ECMA": func() (hashPair, error) {
		h := crc64.New(crc64.MakeTable(crc64.ECMA))
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"crc64_ISO": func() (hashPair, error) {
		h := crc64.New(crc64.MakeTable(crc64.ISO))
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"adler32": func() (hashPair, error) {
		h := adler32.New()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"md5": func() (hashPair, error) {
		h := md5.New()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha1": func() (hashPair, error) {
		h := sha1.New()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha224": func() (hashPair, error) {
		h := sha256.New224()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha384": func() (hashPair, error) {
		h := sha512.New384()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha512/224": func() (hashPair, error) {
		h := sha512.New512_224()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"sha512/256": func() (hashPair, error) {
		h := sha512.New512_256()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
	"ripemd160": func() (hashPair, error) {
		h := ripemd160.New()
		return hashPair{h, func() []byte { return h.Sum(nil) }}, nil
	},
}

// Ensure supportedAlgos is sorted alphabetically
var supportedAlgos = func() []string {
	keys := make([]string, 0, len(hasherMap))
	for k := range hasherMap {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Sort the algorithms alphabetically
	return keys
}()

type Result struct {
	File   string            `json:"file" yaml:"file"`
	Hashes map[string]string `json:"hashes" yaml:"hashes"`
}

type hashPair struct {
	writer io.Writer
	sum    func() []byte
}

func getHasher(name string) (hashPair, error) {
	if constructor, exists := hasherMap[name]; exists {
		return constructor()
	}
	return hashPair{}, fmt.Errorf("unsupported algorithm: %s", name)
}

func getOutputFilename(base, ext string, force bool) (string, error) {
	filename := base + ext
	if force {
		return filename, nil
	}
	for i := 1; ; i++ {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			return filename, nil
		}
		filename = fmt.Sprintf("%s.%d%s", base, i, ext)
	}
}

func hashFileAll(file string, algs []string, format, baseName string, force, toStdout bool) error {
	var input io.ReadSeeker
	displayName := file

	if file == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		input = bytes.NewReader(data)
		displayName = "-"
	} else {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		input = bytes.NewReader(data)
	}

	result := Result{
		File:   displayName,
		Hashes: make(map[string]string),
	}

	for _, alg := range algs {
		hp, err := getHasher(alg)
		if err != nil {
			return err
		}
		input.Seek(0, io.SeekStart)
		if _, err := io.Copy(hp.writer, input); err != nil {
			return err
		}
		result.Hashes[alg] = fmt.Sprintf("%x", hp.sum())
	}

	base := baseName
	if base == "" {
		if file == "-" {
			base = "CHECKSUMS"
		} else {
			base = file
		}
	}

	formats := []string{format}
	if format == "all" {
		formats = []string{"gnu", "json", "yaml"}
	}

	for _, fmtType := range formats {
		var content []byte
		var ext string
		switch fmtType {
		case "gnu":
			ext = ".txt"
			var buf bytes.Buffer
			for alg, digest := range result.Hashes {
				fmt.Fprintf(&buf, "%-12s %s  %s\n", alg, digest, result.File)
			}
			content = buf.Bytes()
		case "bsd":
			ext = ".bsd"
			var buf bytes.Buffer
			for alg, digest := range result.Hashes {
				fmt.Fprintf(&buf, "%s (%s) = %s\n", strings.ToUpper(alg), result.File, digest)
			}
			content = buf.Bytes()
		case "json":
			ext = ".json"
			out, _ := json.MarshalIndent(result, "", "  ")
			content = out
		case "yaml":
			ext = ".yaml"
			out, _ := yaml.Marshal(result)
			content = out
		default:
			return fmt.Errorf("unsupported format: %s", fmtType)
		}

		if toStdout {
			fmt.Print(string(content))
		} else {
			outputFile, err := getOutputFilename(base, ext, force)
			if err != nil {
				return err
			}
			if err := os.WriteFile(outputFile, content, 0644); err != nil {
				return err
			}
			fmt.Printf("Wrote %s\n", outputFile)
		}
	}

	return nil
}

func printHelp() {
	fmt.Printf(
		`NAME
       allsum - compute and check most any message digest

SYNOPSIS
       allsum [OPTION]... [FILE]...

DESCRIPTION
       Print or check various hash algorithm checksums.
       With no FILE, or when FILE is -, read standard input.

OPTIONS
       -alg <list>          Comma-separated list of algorithms (e.g., sha256,blake3), or 'all' (default)
                            Supported algorithms:
				- %s
       -format <type>       Output format: gnu (default), bsd, json, yaml, all
       -name <base>         Base filename (default: input file or CHECKSUMS)
       -f                   Force overwrite of existing files
       -stdout              Output to stdout instead of writing to files
       -h                   Show this help message and exit
`,
		strings.Join(supportedAlgos, "\n                            	- "),
	)
}

func main() {
	algStr := flag.String("alg", "all", "Comma-separated list of algorithms or 'all'")
	format := flag.String("format", "gnu", "Output format: gnu, bsd, json, yaml, all")
	outName := flag.String("name", "", "Base name for output file")
	force := flag.Bool("f", false, "Force overwrite of existing files")
	toStdout := flag.Bool("stdout", false, "Output to stdout instead of writing to files")
	help := flag.Bool("h", false, "Show help")
	listAlgos := flag.Bool("l", false, "List all supported algorithms")
	flag.Parse()

	if *help {
		printHelp()
		return
	}

	if *listAlgos {
		formats := []string{*format}
		if *format == "all" {
			formats = []string{"gnu", "bsd", "json", "yaml"}
		}

		for _, fmtType := range formats {
			switch fmtType {
			case "gnu":
				fmt.Println("Supported algorithms (GNU format):")
				for _, alg := range supportedAlgos {
					fmt.Printf(" - %s\n", alg)
				}
			case "bsd":
				fmt.Println("Supported algorithms (BSD format):")
				for _, alg := range supportedAlgos {
					fmt.Printf("%s\n", alg)
				}
			case "json":
				fmt.Println("Supported algorithms (JSON format):")
				jsonOutput, _ := json.MarshalIndent(supportedAlgos, "", "  ")
				fmt.Println(string(jsonOutput))
			case "yaml":
				fmt.Println("Supported algorithms (YAML format):")
				yamlOutput, _ := yaml.Marshal(supportedAlgos)
				fmt.Println(string(yamlOutput))
			default:
				log.Fatalf("Unsupported format: %s\n", fmtType)
			}
		}
		return
	}

	rawAlgs := strings.Split(*algStr, ",")
	useAll := len(rawAlgs) == 0 || (len(rawAlgs) == 1 && rawAlgs[0] == "all")

	var selectedAlgs []string
	if useAll {
		selectedAlgs = supportedAlgos
	} else {
		for _, alg := range rawAlgs {
			found := false
			for _, valid := range supportedAlgos {
				if alg == valid {
					found = true
					break
				}
			}
			if !found {
				log.Fatalf("Unsupported algorithm: %s\n", alg)
			}
			selectedAlgs = append(selectedAlgs, alg)
		}
	}

	files := flag.Args()
	if len(files) == 0 {
		files = []string{"-"}
	}

	for _, file := range files {
		if err := hashFileAll(file, selectedAlgs, *format, *outName, *force, *toStdout); err != nil {
			log.Fatalf("Error: %v\n", err)
		}
	}
}
