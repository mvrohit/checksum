# Checksum Tool

```
usage: main.py [-h] [-c CHECKSUM] [-a {sha256,md5,sha384,sha512}] file_path

This tool calculates file hash using various algorithms and can also be used to verify checksums.

positional arguments:
  file_path             Path to the file that needs to be verified.

options:
  -h, --help            show this help message and exit
  -c CHECKSUM, --checksum CHECKSUM
                        expected checksum of the file.
  -a {sha256,md5,sha384,sha512}, --algorithm {sha256,md5,sha384,sha512}
                        choose algorithm to calculate checksum, default value is 'sha256'
```