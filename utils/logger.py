import logging


def setup_logger():
    """
    Sets up a logger for the malware scanner application.
    """
    logger = logging.getLogger("MalwareScanner")
    logger.setLevel(logging.INFO)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Format logs
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)

    # Add the handler to the logger
    if not logger.handlers:  # Avoid duplicate handlers
        logger.addHandler(console_handler)

    return logger
