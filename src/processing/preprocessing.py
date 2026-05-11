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
        timestamp = record.get("@timestamp", "")
        sourceip = record.get("client_ip", "N/A")

        http_host = record.get("headers_http_host", "")
        http_method = record.get("headers_http_request_method", "")
        port_service = f"{http_method} {http_host}" if http_method or http_host else "N/A"

        event_description = record.get("sap_function_message", "")

        status = record.get("llm_status", "") or record.get("http_status_code", "") or record.get("sap_function_log_type", "")

        logtype = record.get("sap_function_log_type", "UNKNOWN")

        transformed.append({
            "_id": record.get("_id", ""),
            "timestamp": timestamp,
            "sourceip": sourceip,
            "port_service": port_service,
            "event_description": event_description,
            "status": status,
            "logtype": logtype,
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

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors='coerce')

    numeric_cols = ["http_status_code", "llm_cost_usd", "llm_response_time_ms", "llm_total_tokens", "sap_llm_response_time", "sap_llm_response_size"]
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


def split_by_type(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Separa el DataFrame en:
      - df_system : logs de sistema
      - df_llm    : logs de interacciones LLM
    """
    mask_system = df["logtype"].isin(SYSTEM_LOG_TYPES)
    mask_llm    = df["logtype"].isin(LLM_LOG_TYPES)

    df_system = df[mask_system].copy()
    df_llm    = df[mask_llm].copy()

    for col in LLM_COLS:
        if col in df_system.columns:
            df_system[col] = pd.NA

    for col in SYSTEM_COLS:
        if col in df_llm.columns:
            df_llm[col] = pd.NA

    print(f"[PREPROC] Sistema: {len(df_system)} | LLM: {len(df_llm)}")
    return df_system, df_llm


def flag_security_events(df_system: pd.DataFrame) -> pd.DataFrame:
    """
    Añade columna 'is_security_event'.
    Criterios: tipo SECURITY o ERROR + status >= 400.
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
