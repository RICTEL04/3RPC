import requests
import logging
from config import API_BASE_URL, HEADERS, API_TOKEN
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(levelname)s - %(message)s'
)
logger = logging.getLogger("INGESTION")

def get_window_info() -> dict:
    """
    Llama a /info para conocer total_pages y metadatos
    de la ventana actual antes de iniciar el loop.
    """
    logger.info(f"Conectando a API: {API_BASE_URL}/info")
    logger.debug(f"Token: {API_TOKEN[:20]}..." if API_TOKEN else "Token no configurado")
    
    r = requests.get(f"{API_BASE_URL}/info", headers=HEADERS, timeout=15)
    r.raise_for_status()
    
    info = r.json()
    logger.info(f"Información obtenida - Total páginas: {info['total_pages']}, Total registros: {info['total_records']}")
    logger.info(f"Ventana temporal: {info['window_start']} → {info['window_end']}")
    
    return info


def fetch_page(page: int) -> tuple[int, list]:
    """Retorna los registros de una página específica."""
    url = f"{API_BASE_URL}/logs/current"
    params = {"page": page}
    
    logger.debug(f"Solicitando página {page}: GET {url} params={params}")
    
    r = requests.get(
        url,
        headers=HEADERS,
        params=params,
        timeout=15
    )
    r.raise_for_status()
    
    data = r.json()["data"]
    logger.info(f"Página {page} - Registros obtenidos: {len(data)}")
    
    return page, data


def fetch_all_logs() -> tuple[list[dict], dict]:
    """
    Descarga todas las páginas de la ventana activa.
    Retorna (registros, metadata_de_ventana).
    """
    logger.info("="*70)
    logger.info("INICIANDO INGESTA DE LOGS")
    logger.info("="*70)
    
    # Paso 1: descubrir cuántas páginas hay
    try:
        info = get_window_info()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error al obtener información de ventana: {e}")
        raise
    
    total_pages = info["total_pages"]
    total_records = info["total_records"]

    logger.info(f"Ventana: {info['window_start']} → {info['window_end']}")
    logger.info(f"Configuración - Total registros: {total_records} | Total páginas: {total_pages}")
    logger.info("-"*70)

    # Paso 2: Descargar todas las páginas en paralelo
    logger.info(f"Descargando {total_pages} páginas en paralelo...")
    all_records = []
    
    # Usar ThreadPoolExecutor para descargar en paralelo (máx 5 conexiones simultáneas)
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_page, page): page for page in range(1, total_pages + 1)}
        
        completed = 0
        for future in as_completed(futures):
            page, records = future.result()
            all_records.extend(records)
            completed += 1
            total_acumulado = len(all_records)
            logger.info(f"Progreso: {completed}/{total_pages} páginas | Total acumulado: {total_acumulado} registros")

    logger.info("-"*70)
    logger.info(f"DESCARGA COMPLETADA: {len(all_records)} registros totales desde {total_pages} páginas")
    logger.info("="*70)
    
    return all_records, info