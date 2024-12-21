from config import load_config, save_config
from utils.logger import setup_logger
import psutil
from ipaddress import ip_address, ip_network
from modules.process_identification import inspect_unknown_connections

logger = setup_logger()

# Configuration file details
BASELINE_FILENAME = "network_baseline.json"
DEFAULT_BASELINE = {
    "expected_connections": [
        {"process": "spotify"},
        {"process": "obs"},
        {"process": "obs-browser-page"},
        {"process": "firefox"},
        {"process": "code"},
        {"process": "kdeconnectd"},
    ],
    # TODO Make a list with parent PIDs and also add the children
    "pid_exceptions": [{"pid": "123"}],
    "exceptions": [
        {"remote_address": "192.168.1.1:67"},
        {"remote_address": "0.0.0.0:68"},
    ],
    "private_networks": [
        {"ip_range": "10.0.0.0/8"},
        {"ip_range": "172.16.0.0/12"},
        {"ip_range": "192.168.0.0/16"},
    ],
}


def initialize_baseline():
    logger.info("Initializing network baseline configuration...")
    baseline = load_config(BASELINE_FILENAME, default=DEFAULT_BASELINE)
    if baseline == DEFAULT_BASELINE:
        logger.info("Baseline file not found. Creating a new one with default values.")
        save_config(BASELINE_FILENAME, DEFAULT_BASELINE)
    else:
        logger.info("Baseline configuration loaded successfully.")


def check_network_connections(baseline_filename):
    baseline = load_config(baseline_filename)
    expected_connections = baseline.get("expected_connections", [])
    exceptions = baseline.get("exceptions", [])
    private_networks = baseline.get("private_networks", [])

    for exec in exceptions:
        if not isinstance(exceptions, list) or not isinstance(exec, dict):
            logger.error("Invalid exceptions format. Expected a list of dictionaries.")
            return {"flagged_connections": [], "maybe_malicious": []}

    flagged_connections = []
    maybe_malicious = []

    for conn in psutil.net_connections(kind="inet"):
        try:
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"

            if conn.raddr:
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
            else:
                remote_addr = None

            pid = conn.pid

            if pid:
                process = psutil.Process(pid).name()
            else:
                process = "Unknown"

            # Skip connections without remote address
            if not remote_addr:
                continue

            # Check if connection is in exceptions
            if any(remote_addr == exc.get("remote_address") for exc in exceptions):
                continue

            is_expected = any(
                process == expected.get("process") for expected in expected_connections
            )

            remote_ip = remote_addr.split(":")[0]
            is_private = is_private_ip(remote_ip, private_networks)

            if is_expected or is_private:
                continue
            else:
                flagged_info = {
                    "local_address": local_addr,
                    "remote_address": remote_addr,
                    "pid": pid,
                    "process": process,
                }

                flagged_connections.append(flagged_info)

                if not is_private:
                    maybe_malicious.append(flagged_info)

        except Exception as e:
            logger.error(e)

    # Analyze flagged connections for detailed process information
    logger.info("Analyzing flagged connections for process details...")
    detailed_flagged_connections = inspect_unknown_connections(flagged_connections)

    # Log results
    if detailed_flagged_connections:
        logger.warning(
            f"Detailed flagged connections found: {len(detailed_flagged_connections)}"
        )
        for conn in detailed_flagged_connections:
            logger.warning(f"Flagged (Detailed): {conn}")

    if maybe_malicious:
        logger.warning(
            f"Potentially malicious connections found: {len(maybe_malicious)}"
        )
        for conn in maybe_malicious:
            logger.warning(f"Malicious? {conn}")

    return {
        "flagged_connections": detailed_flagged_connections,
        "maybe_malicious": maybe_malicious,
    }


def is_private_ip(ip, private_networks):
    """Check if an IP address is within private network ranges."""
    try:
        for network in private_networks:
            ip_range = network["ip_range"]
            if ip_address(ip) in ip_network(ip_range):
                return True
        return False
    except ValueError:
        logger.error(f"Invalid IP address: {ip}")
        return False
