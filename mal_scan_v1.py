#Hello!
# This is a script that will scan any folder(s) that you provide on a windows machine for malware.
# It does this by comparing the hashes of all files in the target folder to a database of known malware hashes.
#I have used a database of known malware hashes from a github repository provided by aaryanrlondhe.
#https://github.com/aaryanrlondhe/Malware-Hash-Database/tree/main

#For this script to work, you will need to download the database of known malware hashes from the above link.
#This database of files should be stored in the provided location: C:\Users\Admin\OneDrive\Desktop\Malware Scanner Project\Hashes
#If you wish to store the database in a different location, please change the variable hash_folder in the main function.
#Enjoy!

#import necessary modules
import os
import hashlib
import json

#load the malware hash database
def known_malware_hashes(hash_folder):

    hash_types = ['MD5', 'SHA1', 'SHA256'] #this is the types of hashes we will be looking for and are the names of the folders in the hash database
    known_hashes = {hash_type: set() for hash_type in hash_types}

    if not os.path.exists(hash_folder): #check if the hash folder exists
        print(f"The root folder for known hashes cannot be found at {hash_folder}.")
        return known_hashes
    for hash_type in hash_types:
        folder_path = os.path.join(hash_folder, hash_type)
        if not os.path.exists(folder_path): #check if the hash type folder exists
            print(f"The folder for {hash_type} cannot be found in : {folder_path}.")
            continue

        for root, _, files in os.walk(folder_path):
            print(f"Checking files in {root}") #debugging line to show which folder is being checked
            for file in files:
                if not file.lower().endswith('.txt'):
                    print(f"Skipping non-txt file: {file}") #debugging line to show which files are being skipped
                    continue
                filepath = os.path.join(root, file)
                print(f"Loading hashes from {filepath}") #debugging line to show which file is being loaded
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        for line in f:
                            hash_value = line.strip().lower()
                            if hash_value and len(hash_value) in [32, 40, 64]:
                                known_hashes[hash_type].add(hash_value)
                            else:
                                print(f"Invalid hash in {filepath}: '{hash_value}'") #debugging line to show invalid hashes
                except Exception as e:
                    print(f"Error reading hash file {filepath}: {e.__class__.__name__}: {str(e)}") #more detailed error message
            
        print(f"Loaded {len(known_hashes[hash_type])} {hash_type} hashes.") #debugging line to show how many hashes were loaded for each type
    return known_hashes
                            
#scan all file in a directory for these hashes
def hash_finder(file_path):
    if not os.path.exists(file_path):
        print("File path does not exist.") #debugging line to show which file paths do not exist
        return None
    if not os.path.isfile(file_path): 
        print(f"Skipping non-regular file: {file_path}") #debugging line to show which files are being skipped
        return None
    try:
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as file:
            buf = file.read(65536)
            while len(buf) > 0:
                hash_md5.update(buf)
                hash_sha1.update(buf)
                hash_sha256.update(buf)
                buf = file.read(65536)
        return hash_md5.hexdigest(), hash_sha1.hexdigest(), hash_sha256.hexdigest()
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}.") #debugging line to show which files could not be hashed
        return None

#scan all files in a directory for hashes that match known malware hashes.
def scan_for_malware(target_folders, known_hashes):
    detections = []
    for target_folder in target_folders:
        if not os.path.exists(target_folder):
            print(f"Target folder cannot be found as given: {target_folder}.") #debugging line to show which target folders do not exist
            continue
        for root, _, files in os.walk(target_folder):
            for file in files:
                filepath = os.path.join(root, file)
                try:
                    hashes = hash_finder(filepath)
                    if hashes is None:
                        continue

                    md5_hash, sha1_hash, sha256_hash = hashes

                    if md5_hash in known_hashes['MD5']:
                        detections.append({
                            'file': filepath,
                            'hash_type': 'MD5',
                            'hash': md5_hash,
                            'malware': 'Unknown Malware'
                        })
                        print(f"*** MALWARE DETECTED ***")
                        print(f"*** MALWARE LOCATION: {filepath} ***")
                        print(f"Hash type MD5: {md5_hash}")
                        print(f"--------------------------")
                        
                    if sha1_hash in known_hashes['SHA1']:
                        detections.append({
                            'file': filepath,
                            'hash_type': 'SHA1',
                            'hash': sha1_hash,
                            'malware': 'Unknown Malware'
                        })
                        print(f"*** MALWARE DETECTED ***")
                        print(f"*** MALWARE LOCATION: {filepath} ***")
                        print(f"Hash type SHA1: {sha1_hash}")
                        print(f"--------------------------")

                    if sha256_hash in known_hashes['SHA256']:  
                        detections.append({
                            'file': filepath,
                            'hash_type': 'SHA256',
                            'hash': sha256_hash,
                            'malware': 'Unknown Malware'
                        })
                        print(f"*** MALWARE DETECTED ***")
                        print(f"*** MALWARE LOCATION: {filepath} ***")
                        print(f"Hash type SHA256: {sha256_hash}")
                        print(f"--------------------------")

                except Exception as e:  
                    print(f"Error processing file {filepath}: {e}") #more detailed error message
            
    if not detections:
        print("Congratulations! No malware has been detected in these folder.") #message if no malware is detected
    return detections

#function to get target folders from user input
def get_target_folders():
    print("Please enter the path of the folder(s) you wish to scan for malware.")
    target_folders = []
    while True:
        path =input("> ").strip()
        if not path:
            break
        path = os.path.normpath(path)
        if os.path.exists(path) and os.path.isdir(path):
            target_folders.append(path)
        else:
            print(f"The path {path} is not a valid directory. Please try again.") #error message for invalid directory
    if not target_folders:
        print("*** No valid target folders provided. Exiting program. ***") #error message if no valid target folders are provided
        return None
    return target_folders

#main function to tie everything together!
def main():
    #path to the folder containing known malware hashes
    hash_folder = r'C:\Users\Admin\OneDrive\Desktop\Malware_Scanner_Project\Hashes' 

    # Output file for results (on Desktop)
    output_file = r'C:\Users\Admin\OneDrive\Desktop\Malware_Scanner_Project\scan_results.json'
    
    # Load hashes
    print("Loading malware hashes...")
    known_hashes = known_malware_hashes(hash_folder)
    if not any(known_hashes.values()):
        print("*** No known hashes have been loaded. Exiting program. ***")
        return
    
    #target folder to scan for malware prompt user for input
    print("\nPlease specify the folders to scan for malware.")
    target_folders = get_target_folders()
    if not target_folders:
        return
    
    # Scan for malware
    print("\nStarting scan...")
    detections = scan_for_malware(target_folders, known_hashes)
    
    # Save results
    if detections:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(detections, f, indent=2)
            print(f"\nSaved {len(detections)} detections to {output_file}")
        except Exception as e:
            print(f"Error saving results to {output_file}: {e}")
    else:
        print("\nNo results to save (no detections).")

if __name__ == "__main__":
    main()