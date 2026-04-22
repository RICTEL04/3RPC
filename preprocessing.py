import pandas as pd

# Columnas exclusivas de logs de sistema
SYSTEM_COLS = ["service_id", "http_status_code", "client_ip"]

# Columnas exclusivas de logs LLM
LLM_COLS = ["llm_model_id", "llm_status", "llm_cost_usd", "llm_response_time_ms"]

# Tipos de log por categoría
SYSTEM_LOG_TYPES = {"INFO", "WARNING", "ERROR", "DEBUG", "AUDIT", "PERF", "SECURITY"}
LLM_LOG_TYPES    = {"LLM_REQUEST", "LLM_ERROR", "LLM_TIMEOUT"}


def build_dataframe(records: list[dict]) -> pd.DataFrame:
    """
    Convierte la lista de dicts a DataFrame con el formato CSV requerido,
    incluyendo campos calculados y todos los campos solicitados.
    """
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
            "_score": record.get("_score", ""),
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
    
    # Asegurar que la columna de tiempo sea datetime
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors='coerce')

    # Normalizar tipos numéricos donde aplica
    numeric_cols = ["http_status_code", "llm_cost_usd", "llm_response_time_ms", "llm_total_tokens", "sap_llm_response_time", "sap_llm_response_size"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def split_by_type(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Separa el DataFrame en dos:
      - df_system : logs de sistema (INFO, WARNING, ERROR, AUDIT, PERF, SECURITY, DEBUG)
      - df_llm    : logs de interacciones LLM
    Las columnas vacías por diseño se rellenan con NaN (ya vienen así desde la API).
    """
    mask_system = df["logtype"].isin(SYSTEM_LOG_TYPES)
    mask_llm    = df["logtype"].isin(LLM_LOG_TYPES)

    df_system = df[mask_system].copy()
    df_llm    = df[mask_llm].copy()

    # Columnas LLM deben estar vacías en logs de sistema — forzar NaN para consistencia
    for col in LLM_COLS:
        if col in df_system.columns:
            df_system[col] = pd.NA

    # Columnas de sistema deben estar vacías en logs LLM
    for col in SYSTEM_COLS:
        if col in df_llm.columns:
            df_llm[col] = pd.NA

    print(f"[PREPROC] Sistema: {len(df_system)} | LLM: {len(df_llm)}")
    return df_system, df_llm


def flag_security_events(df_system: pd.DataFrame) -> pd.DataFrame:
    """
    Añade columna 'is_security_event' para facilitar
    el filtrado en el modelo ML y en los dashboards.
    Criterios iniciales: tipo SECURITY o ERROR + status >= 400.
    """
    df = df_system.copy()

    condition = (
        (df["logtype"] == "SECURITY") |
        (
            (df["logtype"] == "ERROR") &
            (df["http_status_code"] >= 400)
        )
    )
    df["is_security_event"] = condition.astype(bool)

    security_count = df["is_security_event"].sum()
    print(f"[PREPROC] Eventos de seguridad marcados: {security_count}")
    return df