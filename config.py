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
HANA_HOST   = os.getenv("HANA_HOST",   "47a6a8bd-d117-4948-a487-39c34f3d2889.hna1.prod-us10.hanacloud.ondemand.com")
HANA_PORT   = int(os.getenv("HANA_PORT", 443))
HANA_USER   = os.getenv("HANA_USER",   "DBADMIN")
HANA_PASS   = os.getenv("HANA_PASS",   "D0nSAPHanaCloudCentral2004")
HANA_SCHEMA = os.getenv("HANA_SCHEMA", "DBADMIN")

# Límite de páginas para pruebas (1 = solo primera página)
MAX_PAGES = int(os.getenv("MAX_PAGES", 1))
