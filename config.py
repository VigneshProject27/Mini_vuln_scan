# ==============================
# NVD API Configuration
# ==============================

NVD_API_KEY = "Your api key"

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

RESULTS_PER_PAGE = 5        # Number of CVEs per query
REQUEST_TIMEOUT = 15        # Seconds before request timeout
RATE_LIMIT_DELAY = 1        # Seconds delay between API calls


# ==============================
# Nmap Configuration
# ==============================

NMAP_ARGUMENTS = "-sS -sV -Pn --version-all"


# ==============================
# Scan Configuration
# ==============================

DEFAULT_PORT_RANGE = "1-1000"   # Change to "1-65535" for full scan
ENABLE_OS_DETECTION = True
ENABLE_VERSION_DETECTION = True


# ==============================
# Reporting Configuration
# ==============================

OUTPUT_FILE = "report.json"
INCLUDE_DESCRIPTION = True
MAX_CVES_PER_SERVICE = 5


# ==============================
# Severity Thresholds (CVSS)
# ==============================

CRITICAL_THRESHOLD = 9.0
HIGH_THRESHOLD = 7.0
MEDIUM_THRESHOLD = 4.0
LOW_THRESHOLD = 0.1
