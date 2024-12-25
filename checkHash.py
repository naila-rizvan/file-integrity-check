import json
import os
import hashlib
import requests
from requests.auth import HTTPBasicAuth

# Path to the directory to monitor
path = "C:/Users/NAILA/Documents/Brototype/Week 13"
json_file = "File Hashes.json"                          # JSON file to store file hashes
current_hashes = {}                                     # Dictionary to store current file hashes

# JIRA Configuration
jira_url = "https://mondebooks.atlassian.net"
jira_proj_key = "KAN"
jira_user = "mondebooks@gmail.com"
jira_api = "ATATT3xFfGF0qQh-UWjd_tspgObVcbbA7CvYtY4oVDbpfUNdFeMrPaFxNyPYsEDEDIEarHCfpzVojdQOpWmxi5vRX-Id_xCJZq3FslcQ_hmoLUeDjfC1GFFpHvvPWO8UloFJhMkWGve0bXSntAdDHRb-zcbbHyMI7HfHaIjUGQa3mnL9vNXBNK8=3CE86BB6"

# Function to list all files in a directory and calculate their hashes
def list_files(path):
    files = os.listdir(path)
    print(path)
    for file in files:
        file_path = os.path.join(path, file)
        if os.path.isdir(file_path):                    # Skip directories
            pass
        else:
            file_hash = generate_hash(file_path)
            current_hashes[file_path] = file_hash

    print(current_hashes)


# Function to generate SHA-256 hash of a file
def generate_hash(file):
    sha256 = hashlib.sha256()
    with open(file,'rb') as open_file:                  # Open file in binary mode
        for line in open_file:
            sha256.update(line)

        return sha256.hexdigest()                       # Return hash as hexadecimal string

# Function to save file hashes to a JSON file
def save_hashes(hashes):
    with open(json_file, "w") as f:
        json.dump(hashes, f, indent=4)

# Function to load file hashes from a JSON file
def load_hashes():
    if not os.path.exists(json_file):
        return {}                                       # Return empty dictionary if file doesn't exist
    else:
        with open(json_file,'r') as f:
            return json.load(f)

# Function to create a JIRA ticket for a detected issue
def create_jira_ticket(summary, desc):
    url = f"{jira_url}/rest/api/3/issue"                # JIRA REST API endpoint
    headers = {"Accept": "application/json",
               "Content-Type": "application/json"}
    data = {
        "fields": {
            "project": {"key": jira_proj_key},
            "summary": summary,
            "description": {                            # ADF formatted description
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {"type": "text", "text": desc}
                        ]
                    }
                ]
            },
            "issuetype": {"name": "Incident"}           # Ticket issue type
        }
    }
    auth = HTTPBasicAuth(jira_user,jira_api)

    # Make POST request to JIRA API to create a ticket
    response = requests.post(url, headers=headers, json=data, auth=auth)

    if response.status_code == 201:
        print("JIRA Ticket created: ", response.json()["key"])
    else:
        print("Failed to create JIRA Ticket: ", response.status_code, response.text)

# Function to check for changes in files and create JIRA tickets for detected issues
def check_file_changes():
    list_files(path)

    previous_hashes = load_hashes()                     # Load previous hashes from JSON
    new_files = []
    changed_files = []
    deleted_files = []

    # Compare current hashes with previous hashes
    for file,hash in current_hashes.items():
        if file not in previous_hashes:
            new_files.append(file)
        elif previous_hashes[file] != hash:
            changed_files.append(file)

    for file in previous_hashes.keys():
        if file not in current_hashes:
            deleted_files.append(file)

    # Create JIRA tickets for each detected change
    for file_path in new_files:
        create_jira_ticket(summary=f"New file detected: {os.path.basename(file_path)}",
                           desc=f"A new file was detected: {file_path}")

    for file_path in changed_files:
        create_jira_ticket(summary=f"File Changed: {os.path.basename(file_path)}",
                           desc=f"The file was modified: {file_path}")

    for file_path in deleted_files:
        create_jira_ticket(summary=f"File Deleted: {os.path.basename(file_path)}",
                           desc=f"The file was deleted: {file_path}")

    # Update current file hashes
    save_hashes(current_hashes)


if __name__ == "__main__":
    check_file_changes()