from utils.logger import setup_logger
from modules.network_scanner import initialize_baseline, check_network_connections
from modules.process_identification import inspect_unknown_connections

logger = setup_logger()

# Configuration file details
BASELINE_FILENAME = "network_baseline.json"


def main():
    logger.info("Starting network scan...")

    # Initialize or load the baseline
    initialize_baseline()

    # Check current network connections against the baseline
    scan_results = check_network_connections(BASELINE_FILENAME)

    flagged_connections = scan_results.get("flagged_connections", [])
    maybe_malicious = scan_results.get("maybe_malicious", [])

    if flagged_connections:
        logger.info(f"Analyzing {len(flagged_connections)} flagged connections...")

        # Use process_identification module to inspect flagged connections
        analyzed_connections = inspect_unknown_connections(flagged_connections)

        # Log detailed results
        logger.info("Detailed analysis of flagged connections:")
        for connection in analyzed_connections:
            logger.info(connection)

    if maybe_malicious:
        logger.warning(
            f"Potentially malicious connections detected: {len(maybe_malicious)}"
        )
        for conn in maybe_malicious:
            logger.warning(conn)

    # Return results for further processing or UI
    return {
        "flagged_connections": flagged_connections,
        "analyzed_connections": analyzed_connections,
        "maybe_malicious": maybe_malicious,
    }


if __name__ == "__main__":
    results = main()
    logger.info("Network scan completed.")
