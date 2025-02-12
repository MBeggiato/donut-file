# Donut File

This project provides a utility to extract and recompile binary dlc files found in The Simpsons: Tapped Out.

## Features

- Extract files from dlc zip
- Recompile extracted files back into a ZIP archive
- Calculate the hash of a ZIP file

## Working with extracted files
If you want to edit the extracted game files, check out this project: https://github.com/al1sant0s/tstorgb


## Requirements

- Python 3.x
- Required Python packages: `argparse`, `zipfile`, `shutil`, `pathlib`, `hashlib`

## Usage

Example decompile:
```sh
python donut-file.py --decompile TheMayflowerMapleBowlBuildDecoGame-100-r496721-6LMZTHC1.zip --log_level debug
```
This creates a folder called TheMayflowerMapleBowlBuildDecoGame-100-r496721-6LMZTHC1.

Example recompile
```sh
python donut-file.py --recompile TheMayflowerMapleBowlBuildDecoGame-100-r496721-6LMZTHC1 --output_dir recompiled --log_level debug
```
This recompiles all files inside the folder TheMayflowerMapleBowlBuildDecoGame-100-r496721-6LMZTHC1 and creates a new archive inside the recompiled folder called TheMayflowerMapleBowlBuildDecoGame-100-r496721-6LMZTHC1.zip


### Decompile
```sh
python donut-file.py --decompile <path_to_zip_file> [--output_dir <output_directory>]
```
### Recompile
```sh
python donut-file.py --recompile <path_to_folder> --output_dir <output_directory>
```
### Calculate hash of file
```sh
python donut-file.py --hash <path_to_zip_file>
```

### Logging
To output a more detailed log, append *--log_level debug* to a command.

## License
This project is licensed under the MIT License.