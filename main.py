import os
from scans import process_scan, file_scan, network_scan
from utils.logger import setup_logger

# Set up logging
logger = setup_logger()


def main():
    logger.info("Starting Malware Scanner...")

    # Step 1: Scan processes
    logger.info("Scanning processes...")
    process_scan.scan()

    # Step 2: Scan files
    logger.info("Scanning files...")
    file_scan.scan()

    # Step 3: Scan network activity
    logger.info("Scanning network activity...")
    network_scan.scan()

    logger.info("Scan completed.")


if __name__ == "__main__":
    main()
