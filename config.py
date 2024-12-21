import os
import json
from utils.logger import setup_logger

logger = setup_logger()

CONFIG_FOLDER = "configs"
os.makedirs(CONFIG_FOLDER, exist_ok=True)


def load_config(filename, default=None):
    file_path = os.path.join(CONFIG_FOLDER, filename)

    if not os.path.exists(file_path):
        logger.info(
            f"Configuration file {filename} not found. Using default configuration."
        )
        return default or {}

    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading configuration file {filename}: {e}")
        return default or {}


def save_config(filename, config):
    file_path = os.path.join(CONFIG_FOLDER, filename)
    try:
        with open(file_path, "w") as f:
            json.dump(config, f, indent=4)
        logger.info(f"Configuration file {filename} saved successfully.")
    except IOError as e:
        logger.error(f"Error saving configuration file {filename}: {e}")
