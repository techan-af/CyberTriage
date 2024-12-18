import json
import re
from datetime import datetime, timedelta
import csv
import os
import yara
import hashlib
import sys

# Function to read file content into the data variable
def load_file_content(file_path):
    with open(file_path, 'r') as file:
        return file.read()

# Example input (replace with actual file paths as needed)
data = load_file_content("ot/bodyfile.txt")  # Replace with your file path

def compute_hash(file_path, hash_type="md5"):
    hash_func = getattr(hashlib, hash_type)()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()

# Function to parse log data (pasted text format)
def parse_data(log_data):
    parsed_entries = []
    for line in log_data.splitlines():
        if re.match(r'^\d+\|', line):  # Check if it's a valid log entry
            fields = line.split('|')
            if len(fields) >= 11:  # Ensure there are enough fields to parse
                entry = {
                    "path": fields[1],
                    "permissions": fields[3],
                    "size": int(fields[2].split('-')[0]),  # Extract size from "10255-48-2"
                    "owner": fields[4] if len(fields) > 4 else "unknown",
                    "group": fields[5] if len(fields) > 5 else "unknown",
                    "created": int(fields[7]),
                    "modified": int(fields[8]),
                    "accessed": int(fields[9]),
                    "changed": int(fields[10]),
                }
                parsed_entries.append(entry)
    return parsed_entries

# Function to parse CSV files
def parse_csv(file_path):
    entries = []
    with open(file_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            entry = {
                "path": row['Path'],
                "permissions": row['Permissions'],
                "size": int(row['Size']),
                "owner": row.get('Owner', 'unknown'),
                "group": row.get('Group', 'unknown'),
                "created": int(row.get('Created', 0)),
                "modified": int(row.get('Modified', 0)),
                "accessed": int(row.get('Accessed', 0)),
                "changed": int(row.get('Changed', 0)),
            }
            entries.append(entry)
    return entries

def detect_iocs(entries):
    """
    Detects Indicators of Compromise (IOCs) based on filesystem entries.

    :param entries: List of dictionaries containing file metadata
    :return: List of detected IOCs, one per file, with consolidated findings
    """
    iocs = []

    # Define thresholds and suspicious criteria
    suspicious_extensions = ['.exe', '.dll', '.bat', '.vbs', '.scr', '.cmd', '.ps1', '.js']
    suspicious_directories = [r'\\$Recycle\.Bin', r'\\$BadClus', r'\\System Volume Information', r'\\Temporary Internet Files']
    unusual_patterns = [r'\bpassword\b', r'\bcredential\b', r'\bhack\b', r'\bmalware\b', r'\bransom\b']  # Add more patterns if needed
    large_file_threshold = 1_000_000_000  # 1GB
    small_file_threshold = 1024  # 1KB
    old_year_threshold = 2000
    inactive_years_threshold = 5
    recent_days_threshold = 7

    now = datetime.now()

    for entry in entries:
        path = entry.get("path", "unknown")
        size = entry.get("size", -1)
        permissions = entry.get("permissions", "")
        owner = entry.get("owner", "unknown").lower()
        group = entry.get("group", "unknown").lower()

        findings = []

        # Check for suspicious permissions
        if permissions == "drwxrwxrwx":
            findings.append("world writable")

        # Check for empty files
        if size == 0:
            findings.append("empty file")

        # Check for hidden or system files
        if path.startswith("."):
            findings.append("hidden file")
        if any(re.search(pattern, path, re.IGNORECASE) for pattern in suspicious_directories):
            findings.append("system directory")

        # Check for suspicious file extensions
        if any(path.endswith(ext) for ext in suspicious_extensions):
            findings.append("suspicious extension")

        # Check for unusual filenames
        if any(re.search(pattern, path, re.IGNORECASE) for pattern in unusual_patterns):
            findings.append("unusual filename")

        # Check for old or outdated timestamps
        created = datetime.fromtimestamp(entry.get("created", 0))
        modified = datetime.fromtimestamp(entry.get("modified", 0))
        accessed = datetime.fromtimestamp(entry.get("accessed", 0))

        if created.year < old_year_threshold:
            findings.append("old creation timestamp")
        if modified.year < old_year_threshold:
            findings.append("old modified timestamp")
        if accessed.year < old_year_threshold:
            findings.append("old access timestamp")

        # Check for inactivity (not accessed or modified in years)
        if modified < now - timedelta(days=inactive_years_threshold * 365):
            findings.append(f"not modified in {inactive_years_threshold}+ years")
        if accessed < now - timedelta(days=inactive_years_threshold * 365):
            findings.append(f"not accessed in {inactive_years_threshold}+ years")

        # Check for suspiciously small or large files
        if size < small_file_threshold:
            findings.append(f"suspiciously small ({size} bytes)")
        elif size > large_file_threshold:
            findings.append(f"suspiciously large ({size} bytes)")

        # Check for unusual ownership or group
        if owner not in ['root', 'administrator']:
            findings.append(f"unusual owner ({entry['owner']})")

        # Check for recently created or modified files
        if created > now - timedelta(days=recent_days_threshold):
            findings.append("recently created")
        if modified > now - timedelta(days=recent_days_threshold):
            findings.append("recently modified")

        # Placeholder for entropy checks
        if "entropy" in entry and entry["entropy"] > 7.5:  # Example threshold
            findings.append(f"high entropy ({entry['entropy']:.2f})")

        # Only add to IOCs if any findings exist
        if findings:
            iocs.append(f"{path}: {', '.join(findings)}")

    return iocs
# Function to save IOCs to a text file
def save_iocs_to_file(ioc_report, output_file):
    with open(output_file, 'a') as file:  # Append to file or create if it doesn't exist
        if ioc_report:
            file.write("Indicators of Compromise detected:\n")
            for ioc in ioc_report:
                file.write("- " + ioc + "\n")
        else:
            file.write("No suspicious indicators found.\n")

# Main execution
def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <output_file>")
        sys.exit(1)

    output_file = sys.argv[1]

    entries = []

    if data.strip():
        entries += parse_data(data)

    try:
        csv_entries = parse_csv("filesystem.csv")  # Replace with actual CSV file path
        entries += csv_entries
    except FileNotFoundError:
        print("No CSV file found to parse.")

    ioc_report = detect_iocs(entries)
    save_iocs_to_file(ioc_report, output_file)

if __name__ == "__main__":
    main()
