import logging
import os


def setup_logger(log_file="linguard.log"):
    """
    Sets up a logger to log messages to both the console and a file.
    Args:
        log_file (str): Name of the log file to write to. Defaults to 'linguard.log'.
    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("LinGuard")
    logger.setLevel(logging.INFO)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create file handler
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)  # Ensure the logs directory exists
    file_handler = logging.FileHandler(os.path.join(log_dir, log_file))
    file_handler.setLevel(logging.INFO)

    # Format logs
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add the handlers to the logger
    if not logger.handlers:  # Avoid duplicate handlers
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    return logger
