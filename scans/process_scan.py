import psutil
import logging
import json
import os

# TODO The list should be update with the latest known malicious processes from Known Online Threat Sources
# Also Figure out a way to check if a process is malicious or not

logger = logging.getLogger("MalwareScanner")


def load_suspicious_processes(file_path="suspicious_processes.json"):
    """
    Load suspicious processes from a JSON file.
    """
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error loading suspicious processes: {e}")
        return []


def scan():
    """
    Scans running processes for suspicious activity.
    """
    logger.info("Starting process scan...")
    suspicious_found = []

    # Load suspicious processes dynamically
    suspicious_processes = load_suspicious_processes()

    # Iterate through all running processes
    for process in psutil.process_iter(["pid", "name"]):
        try:
            process_name = process.info["name"]
            process_id = process.info["pid"]

            # Check if the process is in the suspicious list
            if process_name.lower() in (p.lower() for p in suspicious_processes):
                logger.warning(
                    f"Suspicious process found: {process_name} (PID: {process_id})"
                )
                suspicious_found.append(f"{process_name} (PID: {process_id})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if not suspicious_found:
        logger.info("No suspicious processes found.")
    else:
        logger.info(f"Suspicious processes detected: {', '.join(suspicious_found)}")

    return suspicious_found
