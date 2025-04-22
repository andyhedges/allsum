
# allsum

**allsum** is a command-line utility written in Go that computes cryptographic checksums and hashes using a wide range of algorithms. It supports output in multiple formats and can process files or standard input.

## Features

- Supports over 25 hashing algorithms including SHA, BLAKE, CRC, MD, RIPEMD, Whirlpool, and Streebog.
- Output formats: GNU-style, BSD-style, JSON, YAML.
- Supports checksum generation from files or standard input.
- Outputs to file or stdout.
- Prevents overwriting unless forced.
- Easy to script and automate.

## Supported Algorithms

- adler32  
- blake2b  
- blake2s  
- blake3  
- crc32_Castagnoli  
- crc32_IEEE  
- crc32_Koopman  
- crc64_ECMA  
- crc64_ISO  
- md4  
- md5  
- ripemd160  
- sha1  
- sha224  
- sha256  
- sha3-224  
- sha3-256  
- sha3-384  
- sha3-512  
- sha384  
- sha512  
- sha512/224  
- sha512/256  
- streebog256  
- streebog512  
- whirlpool  

## Installation

### Standard

```bash
go install github.com/andyhedges/allsum@latest
```

### Locally

```bash
git clone https://github.com/andyhedges/allsum.git
cd allsum
go build -o allsum main.go
```

This will create the `allsum` executable in the current directory.

## Usage

```bash
allsum [OPTIONS] [FILE]...
```

If no file is provided or `-` is specified, input is read from standard input.

### Options

| Flag         | Description                                                                 |
|--------------|-----------------------------------------------------------------------------|
| `-alg`       | Comma-separated list of algorithms to use (default: `all`)                  |
| `-format`    | Output format: `gnu` (default), `bsd`, `json`, `yaml`, or `all`             |
| `-name`      | Base name for output file (default: input filename or `CHECKSUMS`)          |
| `-f`         | Force overwrite of existing output files                                     |
| `-stdout`    | Output results to stdout instead of writing to a file                        |
| `-h`         | Show help message and exit                                                   |
| `-l`         | List supported algorithms in the selected format                             |

## Examples

### Generate all checksums in default GNU format for `example.txt`:

```bash
./allsum -alg all example.txt
```

### Use specific algorithms (e.g., SHA256 and BLAKE3):

```bash
./allsum -alg sha256,blake3 example.txt
```

### Output to stdout in YAML format:

```bash
./allsum -alg sha3-512 -format yaml -stdout example.txt
```

### Generate checksums from standard input:

```bash
cat file.bin | ./allsum -alg md5 -
```

### List all supported algorithms in JSON format:

```bash
./allsum -l -format json
```

**allsum** is a helpful tool for generating file integrity checks in multiple formats using many popular (and some less common) hash algorithms. Great for backup verification, forensic tools, or scripting!


## License

This project is licensed under the [MIT License](LICENSE).

**Note:** This software includes dependencies that may be licensed under different terms. Please review the licenses of individual packages for more information.

## Docker

You can build and run `allsum` using Docker for a fully isolated environment.

### Build Docker Image

```bash
docker build -t allsum .
```

### Run allsum in Docker

To run `allsum` and pass a file from your local system:

```bash
docker run --rm -v $(pwd):/data allsum -alg sha256 /data/yourfile.txt
```

### Run with Standard Input

```bash
cat yourfile.txt | docker run --rm -i allsum -alg md5 -
```

This will execute `allsum` inside the Docker container using standard input.
