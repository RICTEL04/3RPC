import os
from dotenv import load_dotenv

# Cargar variables del archivo .env
load_dotenv()

# API Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "https://sap-api-b2.679186.xyz")
API_TOKEN = os.getenv("API_TOKEN", "")

# Construir headers con el token
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

# HANA Configuration
HANA_HOST = os.getenv("HANA_HOST", "")
HANA_PORT = int(os.getenv("HANA_PORT", 443))
HANA_USER = os.getenv("HANA_USER", "")
HANA_PASS = os.getenv("HANA_PASS", "")
HANA_SCHEMA = os.getenv("HANA_SCHEMA", "SOC_LOGS")
