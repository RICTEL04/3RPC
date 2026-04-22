import pandas as pd
from hdbcli import dbapi
from config import HANA_HOST, HANA_PORT, HANA_USER, HANA_PASS, HANA_SCHEMA


def get_connection():
    """Retorna una conexión activa a SAP HANA Cloud."""
    conn = dbapi.connect(
        address=HANA_HOST,
        port=HANA_PORT,
        user=HANA_USER,
        password=HANA_PASS,
        encrypt=True,
        sslValidateCertificate=False  # Ajustar según certificado del ambiente
    )
    return conn


def create_tables_if_not_exist(conn):
    """
    Crea las tablas en HANA si no existen.
    Usa _id como PK y @timestamp para particionamiento de series de tiempo.
    """
    cursor = conn.cursor()

    # Tabla para logs de sistema
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS "{HANA_SCHEMA}"."SYSTEM_LOGS" (
            "_id"                    NVARCHAR(64)  PRIMARY KEY,
            "timestamp"              TIMESTAMP,
            "sap_function_log_type"  NVARCHAR(20),
            "service_id"             NVARCHAR(100),
            "http_status_code"       INTEGER,
            "client_ip"              NVARCHAR(50),
            "is_security_event"      BOOLEAN,
            "raw_json"               NCLOB         -- guarda el registro original completo
        )
    """)

    # Tabla para logs LLM
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS "{HANA_SCHEMA}"."LLM_LOGS" (
            "_id"                    NVARCHAR(64)  PRIMARY KEY,
            "timestamp"              TIMESTAMP,
            "sap_function_log_type"  NVARCHAR(20),
            "llm_model_id"           NVARCHAR(100),
            "llm_status"             NVARCHAR(50),
            "llm_cost_usd"           DECIMAL(10,6),
            "llm_response_time_ms"   INTEGER,
            "raw_json"               NCLOB
        )
    """)

    conn.commit()
    cursor.close()
    print("[HANA] Tablas verificadas/creadas correctamente")


def upsert_batch(conn, df: pd.DataFrame, table: str, columns: list[str]):
    """
    Inserta registros en batch usando UPSERT (INSERT OR REPLACE)
    para evitar duplicados si se reprocesa la misma ventana.
    """
    if df.empty:
        print(f"[HANA] No hay datos para insertar en {table}")
        return

    cursor = conn.cursor()
    cols_str = ", ".join([f'"{c}"' for c in columns])
    placeholders = ", ".join(["?" for _ in columns])

    sql = f'UPSERT "{HANA_SCHEMA}"."{table}" ({cols_str}) VALUES ({placeholders})'

    # Convertir DataFrame a lista de tuplas
    rows = [
        tuple(row[col] if pd.notna(row.get(col)) else None for col in columns)
        for _, row in df.iterrows()
    ]

    cursor.executemany(sql, rows)
    conn.commit()
    cursor.close()
    print(f"[HANA] {len(rows)} registros insertados en {table}")


def load_system_logs(conn, df: pd.DataFrame):
    import json
    df = df.copy()
    df["raw_json"] = df.apply(lambda r: r.to_json(), axis=1)
    df = df.rename(columns={"@timestamp": "timestamp"})

    columns = [
        "_id", "timestamp", "sap_function_log_type",
        "service_id", "http_status_code", "client_ip",
        "is_security_event", "raw_json"
    ]
    upsert_batch(conn, df, "SYSTEM_LOGS", columns)


def load_llm_logs(conn, df: pd.DataFrame):
    df = df.copy()
    df["raw_json"] = df.apply(lambda r: r.to_json(), axis=1)
    df = df.rename(columns={"@timestamp": "timestamp"})

    columns = [
        "_id", "timestamp", "sap_function_log_type",
        "llm_model_id", "llm_status", "llm_cost_usd",
        "llm_response_time_ms", "raw_json"
    ]
    upsert_batch(conn, df, "LLM_LOGS", columns)