"""sailpoint-isc-auditor"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sailpoint-isc-auditor")
except PackageNotFoundError:
    # Package is not installed (e.g. running from source without pip install)
    __version__ = "0.1.0-dev"
