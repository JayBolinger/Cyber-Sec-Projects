# Malware Scanner Project

## Overview
This Python script scans specified folders on a Windows machine for files that match known malware hashes. It compares the MD5, SHA1, and SHA256 hashes of files in the target folder(s) against a database of known malware hashes. If a match is found, the script alerts the user and logs the detection details.

The malware hash database is sourced from [aaryanrlondhe's Malware Hash Database](https://github.com/aaryanrlondhe/Malware-Hash-Database).

## Requirements
- **Python 3.x** installed on your Windows machine.
- The `hashlib`, `os`, and `json` Python modules (included in the standard library).
- The malware hash database from the above GitHub repository, stored in the specified directory (default: `C:\Users\Admin\OneDrive\Desktop\Malware_Scanner_Project\Hashes`).

## Setup
1. **Download the Malware Hash Database**:
   - Clone or download the database from [aaryanrlondhe's GitHub repository](https://github.com/aaryanrlondhe/Malware-Hash-Database).
   - Place the `Hashes` folder in the default location: `C:\Users\Admin\OneDrive\Desktop\Malware_Scanner_Project\Hashes`.
   - Alternatively, update the `hash_folder` variable in the `main()` function to point to your preferred location.

2. **Install Python**:
   - Ensure Python 3.x is installed. You can download it from [python.org](https://www.python.org/downloads/).

3. **Prepare the Script**:
   - Save the provided Python script (e.g., `malware_scanner.py`) to your desired location.
   - Ensure the script has access to the `Hashes` folder.

## Usage
- Run the script using Python on cmd or Powershell
- python malware_scanner.py
  