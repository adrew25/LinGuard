import ipaddress
from utils import logger


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        logger.error(f"Invalid IP address detected: {ip}")
