#!/usr/bin/env python3
import os
import hashlib
import argparse
from enum import Enum
import logging
from typing import Optional

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


class Algorithm(Enum):
    SHA256 = "sha256"
    MD5 = "md5"
    SHA384 = "sha384"
    SHA512 = "sha512"


ALGO_FUNCTIONS = {
    Algorithm.SHA256: hashlib.sha256,
    Algorithm.MD5: hashlib.md5,
    Algorithm.SHA384: hashlib.sha384,
    Algorithm.SHA512: hashlib.sha512,
}


def calculate_checksum(file_path: str, algorithm: Algorithm) -> Optional[str]:
    """Calculate the checksum of a file using the specified algorithm."""
    hash_func = ALGO_FUNCTIONS[algorithm]()
    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):
                hash_func.update(chunk)
            return hash_func.hexdigest()
    except OSError as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None


def verify_checksum(file_path: str, expected_checksum: str, algorithm: Algorithm) -> bool:
    """Verify the checksum of a file against the expected value."""
    calculated_checksum = calculate_checksum(file_path, algorithm)
    if calculated_checksum == expected_checksum:
        logging.info(f"{algorithm.value} Checksums match!")
        return True
    else:
        logging.warning(f"{algorithm.value} Checksums do not match!")
        logging.info(f"Calculated {algorithm.value}: {calculated_checksum}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="This tool calculates file hash using various algorithms and can also be used to verify checksums.")
    parser.add_argument("file_path", type=str,
                        help="Path to the file that needs to be verified.")
    parser.add_argument("-c", "--checksum", type=str,
                        help="expected checksum of the file.")
    parser.add_argument("-a", "--algorithm", type=str, default=Algorithm.SHA256.value, choices=[
        algo.value for algo in Algorithm],
                        help=f"choose algorithm to calculate checksum, default value is '{Algorithm.SHA256.value}'")

    args = parser.parse_args()
    file_path = args.file_path
    expected_checksum = args.checksum
    try:
        algorithm = Algorithm(args.algorithm)
    except ValueError:
        logging.error(f"Invalid algorithm type: {args.algorithm}")
        return

    if os.path.exists(file_path):
        if expected_checksum is not None:
            if verify_checksum(file_path, expected_checksum, algorithm):
                logging.info("Verification succeeded.")
            else:
                logging.info("Verification failed.")
        else:
            calculated_checksum = calculate_checksum(file_path, algorithm)
            if calculated_checksum:
                logging.info(f"Calculated {algorithm.value}: {calculated_checksum}")
    else:
        logging.error(f"file {file_path} does not exist")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.warning("Process interrupted by user.")
