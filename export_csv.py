import os
from datetime import datetime
import pandas as pd
import requests
import logging
from config import API_BASE_URL, HEADERS
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(name)s] - %(levelname)s - %(message)s'
)
logger = logging.getLogger("EXPORT_CSV")


def fetch_logs_from_api():
    """
    Descarga todos los logs de la API actual usando paginación paralela.
    Retorna lista de registros sin procesar.
    """
    logger.info("="*70)
    logger.info("INICIANDO DESCARGA DE API")
    logger.info("="*70)
    
    try:
        # Paso 1: Obtener información de la ventana (endpoint /info)
        logger.info(f"Conectando a API: {API_BASE_URL}/info")
        r = requests.get(f"{API_BASE_URL}/info", headers=HEADERS, timeout=15, verify=False)
        r.raise_for_status()
        
        info = r.json()
        total_pages = info["total_pages"]
        total_records = info["total_records"]
        
        logger.info(f"Ventana: {info['window_start']} → {info['window_end']}")
        logger.info(f"Total registros: {total_records} | Total páginas: {total_pages}")
        logger.info("-"*70)
        
        # Paso 2: Descargar todas las páginas en paralelo
        logger.info(f"Descargando {total_pages} páginas en paralelo...")
        all_records = []
        
        def fetch_page(page: int) -> tuple[int, list]:
            """Descarga una página específica de forma paralela."""
            try:
                r = requests.get(
                    f"{API_BASE_URL}/logs/current",
                    headers=HEADERS,
                    params={"page": page},
                    timeout=15,
                    verify=False
                )
                r.raise_for_status()
                records = r.json()["data"]
                logger.info(f"  ✓ Página {page}/{total_pages} descargada: {len(records)} registros")
                return page, records
            except Exception as e:
                logger.error(f"  ✗ Error en página {page}: {e}")
                return page, []
        
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
        
        return all_records
    
    except requests.exceptions.RequestException as e:
        logger.error(f"Error al descargar datos de API: {e}")
        raise
    except Exception as e:
        logger.error(f"Error inesperado: {e}")
        raise


def transform_logs_to_csv_format(records: list) -> pd.DataFrame:
    """
    Transforma los registros raw de la API al formato CSV requerido:
    - timestamp
    - sourceip
    - port_service
    - event_description
    - status
    - logtype
    """
    logger.info("Transformando registros al formato requerido...")
    
    transformed = []
    for record in records:
        # Extraer campos del registro
        timestamp = record.get("@timestamp", "")
        sourceip = record.get("client_ip", "N/A")
        
        # Construir port_service desde headers
        http_host = record.get("headers_http_host", "")
        http_method = record.get("headers_http_request_method", "")
        port_service = f"{http_method} {http_host}" if http_method or http_host else "N/A"
        
        # Descripción del evento
        event_description = record.get("sap_function_message", "")
        
        # Estado - determinar según campos disponibles
        status = record.get("llm_status", "") or record.get("http_status_code", "") or record.get("sap_function_log_type", "")
        
        # Tipo de log
        logtype = record.get("sap_function_log_type", "UNKNOWN")
        
        transformed.append({
            # Campos originales
            "_id": record.get("_id", ""),
            "timestamp": timestamp,
            "sourceip": sourceip,
            "port_service": port_service,
            "event_description": event_description,
            "status": status,
            "logtype": logtype,
            # Campos nuevos solicitados
            "region_id": record.get("region_id", ""),
            "region_name": record.get("region_name", ""),
            "region_code": record.get("region_code", ""),
            "macro_region": record.get("macro_region", ""),
            "sap_llm_response_time": record.get("sap_llm_response_time", ""),
            "sap_llm_response_size": record.get("sap_llm_response_size", ""),
            "llm_cost_usd": record.get("llm_cost_usd", ""),
            "headers_http_request_method": record.get("headers_http_request_method", ""),
            "llm_model_id": record.get("llm_model_id", ""),
            "sap_app_env": record.get("sap_app_env", ""),
            "llm_finish_reason": record.get("llm_finish_reason", ""),
            "llm_temperature": record.get("llm_temperature", ""),
            "http_status_code": record.get("http_status_code", ""),
            "llm_response_time_ms": record.get("llm_response_time_ms", ""),
            "llm_total_tokens": record.get("llm_total_tokens", ""),
            "llm_status": record.get("llm_status", ""),
            "llm_prompt": record.get("llm_prompt", "")
        })
    
    df = pd.DataFrame(transformed)
    logger.info(f"Transformación completada: {len(df)} registros procesados")
    return df


def export_to_csv():
    """
    Descarga logs de la API real y los exporta a tres CSVs:
    - LOGS_EXPORT_{timestamp}.csv: Todos los logs
    - LOGS_LLM_{timestamp}.csv: Solo logs de LLM (logtype empieza con 'LLM')
    - LOGS_SYSTEM_{timestamp}.csv: Logs del sistema (logtype no empieza con 'LLM')
    """
    print("\n" + "="*60)
    print("[EXPORT CSV] Iniciando exportación de datos reales a tres CSVs...")
    
    try:
        # 1. Descargar datos de la API
        records = fetch_logs_from_api()
        
        # 2. Transformar al formato requerido
        df = transform_logs_to_csv_format(records)
        
        # 3. Filtrar logs LLM y sistema
        df_llm = df[df['logtype'].str.startswith('LLM')]
        df_system = df[~df['logtype'].str.startswith('LLM')]
        
        # 4. Remover columnas específicas para cada CSV
        # Para LLM logs: quitar 'sourceip'
        df_llm = df_llm.drop(columns=['sourceip'])
        # Para system logs: quitar columnas que contengan 'llm'
        llm_columns = [col for col in df_system.columns if 'llm' in col.lower()]
        df_system = df_system.drop(columns=llm_columns)
        
        # 5. Guardar a CSV
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = "exports"
        os.makedirs(output_dir, exist_ok=True)
        
        csv_file = f"{output_dir}/LOGS_EXPORT_{timestamp}.csv"
        df.to_csv(csv_file, index=False, encoding='utf-8')
        
        csv_llm_file = f"{output_dir}/LOGS_LLM_{timestamp}.csv"
        df_llm.to_csv(csv_llm_file, index=False, encoding='utf-8')
        
        csv_system_file = f"{output_dir}/LOGS_SYSTEM_{timestamp}.csv"
        df_system.to_csv(csv_system_file, index=False, encoding='utf-8')
        
        logger.info("="*70)
        logger.info(f"CSV principal exportado exitosamente: {csv_file}")
        logger.info(f"Total registros: {len(df)} | Columnas: {', '.join(df.columns)}")
        logger.info(f"CSV LLM exportado: {csv_llm_file} ({len(df_llm)} registros) | Columnas: {', '.join(df_llm.columns)}")
        logger.info(f"CSV Sistema exportado: {csv_system_file} ({len(df_system)} registros) | Columnas: {', '.join(df_system.columns)}")
        logger.info("="*70)
        
        print(f"\n✓ Archivo principal guardado: {csv_file}")
        print(f"✓ Registros exportados: {len(df)} | Columnas: {', '.join(df.columns)}")
        print(f"✓ Archivo LLM guardado: {csv_llm_file} ({len(df_llm)} registros) | Columnas: {', '.join(df_llm.columns)}")
        print(f"✓ Archivo Sistema guardado: {csv_system_file} ({len(df_system)} registros) | Columnas: {', '.join(df_system.columns)}")
        
    except Exception as e:
        logger.error(f"ERROR en exportación: {e}")
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    export_to_csv()

