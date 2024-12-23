# Donut File

This project provides a utility to extract and recompile binary dlc files found in The Simpsons: Tapped Out.

## Features

- Extract files from dlc zip
- Recompile extracted files back into a ZIP archive
- Calculate the hash of a ZIP file

## Planed features
- Add a decompile function for the following file formats
  - [ ] rgb
  - [ ] bsv3
  - [ ] bcell
- Add a recompile function for the following file formats
  - [ ] rgb
  - [ ] bsv3
  - [ ] bcell

## Requirements

- Python 3.x
- Required Python packages: `argparse`, `zipfile`, `shutil`, `pathlib`, `hashlib`

## Usage

### Decompile
```sh
python donut-file.py --decompile <path_to_zip_file> [--output_dir <output_directory>]
```
### Recompile
```sh
python donut-file.py --recompile <path_to_folder>
```
### Calculate hash of file
```sh
python donut-file.py --hash <path_to_zip_file>
```
## License
This project is licensed under the MIT License.