import os
from functools import lru_cache

try:
    import yaml
except ImportError as e:
    raise ImportError(
        "Missing dependency: PyYAML. Install it using: pip install pyyaml"
    ) from e


class ConfigLoadError(Exception):
    """Custom exception for configuration load failures."""


@lru_cache(maxsize=1)
def load_config(path: str = None) -> dict:
    """
    Load and cache configuration from a YAML file.

    Args:
        path (str): Optional path to config file. Defaults to env CONFIG_PATH or 'config.yaml'.

    Returns:
        dict: Parsed YAML configuration.

    Raises:
        ConfigLoadError: For YAML parsing errors or invalid structure.
        FileNotFoundError: If the config file is not found.
    """
    path = path or os.getenv("CONFIG_PATH", "config.yaml")

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")

    try:
        with open(path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigLoadError(f"Failed to parse YAML: {e}") from e

    if not isinstance(config, dict):
        raise ConfigLoadError("Root of config must be a dictionary.")

    return config