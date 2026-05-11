import os
from dotenv import load_dotenv

load_dotenv()

# API Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "https://sap-api-b2.679186.xyz")
API_TOKEN    = os.getenv("API_TOKEN", "")

HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# HANA Configuration — valores cargados desde .env (ver .env.example)
HANA_HOST   = os.getenv("HANA_HOST",   "")
HANA_PORT   = int(os.getenv("HANA_PORT", 443))
HANA_USER   = os.getenv("HANA_USER",   "")
HANA_PASS   = os.getenv("HANA_PASS",   "")
HANA_SCHEMA = os.getenv("HANA_SCHEMA", "")

# Límite de páginas (0 = sin límite, descarga todas)
MAX_PAGES = int(os.getenv("MAX_PAGES", 0))
