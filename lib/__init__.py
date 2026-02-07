"""
Purple Team Portable - Shared Library
"""

from .paths import paths, get_paths, setup_python_path
from .config import config, get_config, load_config

__all__ = [
    'paths', 'get_paths', 'setup_python_path',
    'config', 'get_config', 'load_config'
]
