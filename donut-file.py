import os
import argparse
import zipfile
import shutil
from pathlib import Path
import hashlib

def parse_binary_file(file_path):
    """
    Parses the binary `0` file to extract file references.
    """
    try:
        with open(file_path, "rb") as file:
            data = file.read()
        return filter_file_references(extract_strings(data))
    except Exception as e:
        print(f"Error parsing binary file: {e}")
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
    

    print(f"Number of strings: {len(strings)}")
    # check for duplicates and remove them
    strings = list(set(strings))
    print(f"Number of unique strings: {len(strings)}")
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
            print(f"`0` file not found in the top-level ZIP.")
            return
        
        referenced_files = parse_binary_file(file_0_path)
        nested_zip_path = os.path.join(output_dir, "1")
        if not os.path.exists(nested_zip_path):
            print(f"Nested ZIP `1` not found.")
            return

        extract_referenced_files(nested_zip_path, referenced_files, output_dir)
    except Exception as e:
        print(f"Error extracting files from ZIP: {e}")

def extract_zip(zip_path, output_dir):
    """
    Extracts a ZIP file to the specified output directory.
    """
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        print(f"Extracting ZIP: {zip_path}")
        zip_ref.extractall(output_dir)

def extract_referenced_files(nested_zip_path, referenced_files, output_dir):
    """
    Extracts the referenced files from the nested ZIP archive.
    """
    with zipfile.ZipFile(nested_zip_path, "r") as nested_zip:
        for file_name in nested_zip.namelist():
            print(f"Extracting {file_name} from nested ZIP.")
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
    parser.add_argument("zip_path", help="Path to the top-level ZIP file")
    parser.add_argument(
        "--output_dir",
        help="Directory to extract the files into (default: name of the ZIP file without extension)",
        nargs="?",  # Makes the argument optional
    )
    parser.add_argument(
        "--decompile",
        action="store_true",
        help="Signal the program to extract the ZIP file"
    )
    parser.add_argument(
        "--recompile",
        action="store_true",
        help="Signal the program to recompile the ZIP file"
    )
    parser.add_argument(
        "--hash",
        action="store_true",
        help="Calculate the hash of the recompiled ZIP file"
    )

    args = parser.parse_args()

    if args.hash and args.zip_path:
        zip_file_hash = calculate_file_hash(args.zip_path)
        print(f"Hash of the ZIP file: {zip_file_hash}")

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
            print(f"Output directory {output_dir} already exists. Deleting it.")
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
        output_dir = args.output_dir
        base_name = os.path.basename(output_dir.rstrip('/\\'))
        base_zip_path = f"{base_name}.zip"
        nested_zip_path = os.path.join(output_dir, "1.zip")

        # Create the nested ZIP archive
        with zipfile.ZipFile(nested_zip_path, "w", zipfile.ZIP_DEFLATED) as nested_zip:
            nested_dir = os.path.join(output_dir, "1")
            for root, _, files in os.walk(nested_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=nested_dir)
                    nested_zip.write(file_path, arcname)

        # Create the base ZIP archive
        with zipfile.ZipFile(base_zip_path, "w", zipfile.ZIP_DEFLATED) as base_zip:
            file_0_path = os.path.join(output_dir, "0")
            if os.path.exists(file_0_path):
                base_zip.write(file_0_path, "0")
            base_zip.write(nested_zip_path, "1")

        print(f"Recompiled ZIP file created at: {base_zip_path}")
        

if __name__ == "__main__":
    main()
