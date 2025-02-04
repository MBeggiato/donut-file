import os
import argparse
import zipfile
import shutil
from pathlib import Path
import hashlib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_binary_file(file_path):
    """
    Parses the binary `0` file to extract file references.
    """
    try:
        with open(file_path, "rb") as file:
            data = file.read()
        return filter_file_references(extract_strings(data))
    except Exception as e:
        logging.error(f"Error parsing binary file: {e}")
        return []

def extract_strings(data, min_length=4):
    """
    Extract printable ASCII strings from binary data.
    """
    strings = []
    current_string = ""

    for byte in data:
        if 32 <= byte <= 126:  # Printable ASCII
            current_string += chr(byte)
        elif len(current_string) >= min_length:
            strings.append(current_string)
            current_string = ""
        else:
            current_string = ""

    if len(current_string) >= min_length:
        strings.append(current_string)
    
    logging.info(f"Number of strings: {len(strings)}")
    # check for duplicates and remove them
    strings = list(set(strings))
    logging.info(f"Number of unique strings: {len(strings)}")
    return strings

def filter_file_references(strings):
    """
    Filter file-like references from a list of strings.
    """
    return [s for s in strings if s.endswith((".bga", ".h", ".xml", ".rgb", ".png", ".bsv3", ".bcell"))]

def extract_files_from_zip(zip_path, output_dir, file_0_path):
    """
    Extracts the files referenced in the `0` file from the nested ZIP archive.
    """
    try:
        extract_zip(zip_path, output_dir)
        if not os.path.exists(file_0_path):
            logging.warning(f"`0` file not found in the top-level ZIP.")
            return
        
        referenced_files = parse_binary_file(file_0_path)
        nested_zip_path = os.path.join(output_dir, "1")
        if not os.path.exists(nested_zip_path):
            logging.warning(f"Nested ZIP `1` not found.")
            return

        extract_referenced_files(nested_zip_path, referenced_files, output_dir)
    except Exception as e:
        logging.error(f"Error extracting files from ZIP: {e}")

def extract_zip(zip_path, output_dir):
    """
    Extracts a ZIP file to the specified output directory.
    """
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        logging.info(f"Extracting ZIP: {zip_path}")
        zip_ref.extractall(output_dir)

def extract_referenced_files(nested_zip_path, referenced_files, output_dir):
    """
    Extracts the referenced files from the nested ZIP archive.
    """
    with zipfile.ZipFile(nested_zip_path, "r") as nested_zip:
        for file_name in nested_zip.namelist():
            logging.info(f"Extracting {file_name} from nested ZIP.")
            nested_zip.extract(file_name, os.path.join(output_dir, "extracted_files"))

def calculate_file_hash(file_path, hash_algo=hashlib.sha256):
    """
    Calculate the hash of a file.
    """
    hash_obj = hash_algo()
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

def main():
    parser = argparse.ArgumentParser(
        description="Extract files from nested ZIP archives based on a binary 0 file."
    )
    parser.add_argument("zip_path", help="Path to the top-level ZIP file", nargs="?")
    parser.add_argument(
        "--output_dir",
        help="Directory to extract the files into or where the packed ZIP should be created (default: name of the ZIP file without extension)",
        nargs="?",  # Makes the argument optional
    )
    parser.add_argument(
        "--decompile",
        action="store_true",
        help="Signal the program to extract the ZIP file"
    )
    parser.add_argument(
        "--recompile",
        help="Directory to recompile into a ZIP file"
    )
    parser.add_argument(
        "--hash",
        action="store_true",
        help="Calculate the hash of the recompiled ZIP file"
    )
    parser.add_argument(
        "--log_level",
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
        default="INFO"
    )

    args = parser.parse_args()

    # Set logging level based on the argument
    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {args.log_level}")
    logging.getLogger().setLevel(numeric_level)

    if args.hash and args.zip_path:
        zip_file_hash = calculate_file_hash(args.zip_path)
        logging.info(f"Hash of the ZIP file: {zip_file_hash}")

    if args.decompile and args.zip_path:
        zip_path = args.zip_path
        # Set default output directory based on the ZIP file name
        if args.output_dir:
            output_dir = args.output_dir
        else:
            zip_base_name = os.path.splitext(os.path.basename(zip_path))[0]
            output_dir = os.path.join(os.getcwd(), zip_base_name)

        # Check if the output directory already exists and delete it if it does
        if os.path.exists(output_dir):
            logging.info(f"Output directory {output_dir} already exists. Deleting it.")
            shutil.rmtree(output_dir)
        # Ensure the output directory exists
        os.makedirs(output_dir, exist_ok=True)
        # Extract files
        file_0_path = os.path.join(output_dir, "0")
        file_1_path = os.path.join(output_dir, "1")
        extract_files_from_zip(zip_path, output_dir, file_0_path)
        
        os.remove(file_1_path)
        os.rename(os.path.join(output_dir, "extracted_files"), file_1_path)

    if args.recompile and args.output_dir:
        recompile_dir = args.recompile
        output_dir = args.output_dir

        # Ensure the output directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        logging.debug("Recompiling ZIP file")
        logging.debug(f"Recompile directory: {recompile_dir}")
        logging.debug(f"Output directory: {output_dir}")
        base_name = os.path.basename(recompile_dir.rstrip('/\\'))
        logging.debug(f"Base name: {base_name}")
        base_zip_path = os.path.join(output_dir, f"{base_name}.zip")
        logging.debug(f"Base ZIP path: {base_zip_path}")
        nested_zip_path = os.path.join(recompile_dir, "1.zip")
        logging.debug(f"Nested ZIP path: {nested_zip_path}")

        # Create the nested ZIP archive
        with zipfile.ZipFile(nested_zip_path, "w", zipfile.ZIP_DEFLATED) as nested_zip:
            logging.debug(f"Creating nested ZIP archive: {nested_zip_path}")
            nested_dir = os.path.join(recompile_dir, "1")
            logging.debug(f"Nested directory: {nested_dir}")
            for root, _, files in os.walk(nested_dir):
                logging.debug(f"Root: {root}")
                for file in files:
                    logging.debug(f"File: {file}")
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=nested_dir)
                    nested_zip.write(file_path, arcname)

        # Create the base ZIP archive
        with zipfile.ZipFile(base_zip_path, "w", zipfile.ZIP_DEFLATED) as base_zip:
            logging.debug(f"Creating base ZIP archive: {base_zip_path}")
            file_0_path = os.path.join(recompile_dir, "0")
            logging.debug(f"0 file path: {file_0_path}")
            if os.path.exists(file_0_path):
                logging.debug(f"Adding 0 file to base ZIP")
                base_zip.write(file_0_path, "0")
            base_zip.write(nested_zip_path, "1")
            logging.debug(f"Adding nested ZIP to base ZIP")

        logging.info(f"Recompiled ZIP file created at: {base_zip_path}")

if __name__ == "__main__":
    main()
