import subprocess
import socket
import psutil
from utils.logger import setup_logger
from utils.ip_helpers import validate_ip

logger = setup_logger()


def resolve_ip(ip_address):
    try:
        if not validate_ip(ip_address):
            return "Unknown"
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        logger.warning(f"Hostname resolution failed for IP: {ip_address}")
        return "Unknown"
    except Exception as e:
        logger.error(f"Error during hostname resolution for IP {ip_address}")
        return "Unknown"


def find_process_by_port(port):
    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        if result.returncode == 0:
            lines = result.stdout.strip().split("\n")
            if len(lines) > 1:
                details = lines[1].split()
                return {"pid": int(details), "process_name": details[0]}
        return {"pid": None, "process_name": "Unknown"}

    except Exception as e:
        return {"pid": None, "process_name": str(e)}


def list_subprocesses(pid):
    try:
        result = []
        parrent = psutil.Process(pid)
        children = parrent.children(recursive=True)
        for child in children:
            subprc = {"pid": child.pid, "process_name": child.name()}
            result.append(subprc)

        return result
    except psutil.NoSuchProcess:
        result = []
        return result


def inspect_unknown_connections(connections):
    identified = []

    for conn in connections:
        local_address = conn.get("local_address", "Unknown").split(":")
        remote_address = conn.get("remote_address", "Unknown")

        # Extract port
        if len(local_address) > 1:
            port = local_address[-1]
        else:
            port = "Unknown"

        # Default process_info to avoid unbound variable
        process_info = {"pid": None, "process_name": "Unknown"}

        # Get process info if the port is valid
        if port.isdigit():
            process_info = find_process_by_port(port)

        # Get subprocesses if process_info has a valid PID
        subprocesses = []
        if process_info["pid"]:
            subprocesses = list_subprocesses(process_info["pid"])

        # Resolve domain for remote address
        domain = resolve_ip(remote_address.split(":")[0])

        # Append identified connection details
        identified.append(
            {
                "local_address": conn.get("local_address", "Unknown"),
                "remote_address": conn.get("remote_address", "Unknown"),
                "process_name": process_info["process_name"],
                "pid": process_info["pid"],
                "subprocesses": subprocesses,
                "remote_domain": domain,
            }
        )

    return identified
