import pandas as pd
from hdbcli import dbapi
from config import HANA_HOST, HANA_PORT, HANA_USER, HANA_PASS, HANA_SCHEMA

# Columnas exactas de cada tabla (espejo de los CSVs)
SYSTEM_COLS = [
    "_id", "timestamp", "sourceip", "port_service", "event_description",
    "status", "logtype", "region_id", "region_name", "region_code",
    "macro_region", "_score", "headers_http_request_method",
    "sap_app_env", "http_status_code", "is_security_event",
]

LLM_COLS = [
    "_id", "timestamp", "port_service", "event_description", "status",
    "logtype", "region_id", "region_name", "region_code", "macro_region",
    "sap_llm_response_time", "sap_llm_response_size", "llm_cost_usd",
    "_score", "headers_http_request_method", "llm_model_id", "sap_app_env",
    "llm_finish_reason", "llm_temperature",
    "llm_response_time_ms", "llm_total_tokens", "llm_status", "llm_prompt",
]

SYSTEM_DDL = f"""
    CREATE TABLE "{HANA_SCHEMA}"."SYSTEM_LOGS" (
        "_id"                        NVARCHAR(64)   PRIMARY KEY,
        "timestamp"                  TIMESTAMP,
        "sourceip"                   NVARCHAR(50),
        "port_service"               NVARCHAR(200),
        "event_description"          NVARCHAR(500),
        "status"                     NVARCHAR(50),
        "logtype"                    NVARCHAR(20),
        "region_id"                  NVARCHAR(20),
        "region_name"                NVARCHAR(100),
        "region_code"                NVARCHAR(20),
        "macro_region"               NVARCHAR(50),
        "_score"                     DECIMAL(10,4),
        "headers_http_request_method" NVARCHAR(20),
        "sap_app_env"                NVARCHAR(50),
        "http_status_code"           INTEGER,
        "is_security_event"          TINYINT
    )
"""

LLM_DDL = f"""
    CREATE TABLE "{HANA_SCHEMA}"."LLM_LOGS" (
        "_id"                        NVARCHAR(64)   PRIMARY KEY,
        "timestamp"                  TIMESTAMP,
        "port_service"               NVARCHAR(200),
        "event_description"          NVARCHAR(500),
        "status"                     NVARCHAR(50),
        "logtype"                    NVARCHAR(20),
        "region_id"                  NVARCHAR(20),
        "region_name"                NVARCHAR(100),
        "region_code"                NVARCHAR(20),
        "macro_region"               NVARCHAR(50),
        "sap_llm_response_time"      DECIMAL(12,4),
        "sap_llm_response_size"      DECIMAL(14,2),
        "llm_cost_usd"               DECIMAL(10,6),
        "_score"                     DECIMAL(10,4),
        "headers_http_request_method" NVARCHAR(20),
        "llm_model_id"               NVARCHAR(100),
        "sap_app_env"                NVARCHAR(50),
        "llm_finish_reason"          NVARCHAR(50),
        "llm_temperature"            DECIMAL(5,2),
        "llm_response_time_ms"       DECIMAL(12,4),
        "llm_total_tokens"           INTEGER,
        "llm_status"                 NVARCHAR(50),
        "llm_prompt"                 NCLOB
    )
"""

# Columnas a migrar en tablas existentes: (nombre, tipo HANA)
SYSTEM_MIGRATE = [
    ("port_service",               "NVARCHAR(200)"),
    ("event_description",          "NVARCHAR(500)"),
    ("status",                     "NVARCHAR(50)"),
    ("logtype",                    "NVARCHAR(20)"),
    ("region_id",                  "NVARCHAR(20)"),
    ("region_name",                "NVARCHAR(100)"),
    ("region_code",                "NVARCHAR(20)"),
    ("macro_region",               "NVARCHAR(50)"),
    ("_score",                     "DECIMAL(10,4)"),
    ("headers_http_request_method","NVARCHAR(20)"),
    ("sap_app_env",                "NVARCHAR(50)"),
    ("sourceip",                   "NVARCHAR(50)"),
    ("is_security_event",          "TINYINT"),
]

LLM_MIGRATE = [
    ("port_service",               "NVARCHAR(200)"),
    ("event_description",          "NVARCHAR(500)"),
    ("status",                     "NVARCHAR(50)"),
    ("logtype",                    "NVARCHAR(20)"),
    ("region_id",                  "NVARCHAR(20)"),
    ("region_name",                "NVARCHAR(100)"),
    ("region_code",                "NVARCHAR(20)"),
    ("macro_region",               "NVARCHAR(50)"),
    ("sap_llm_response_time",      "DECIMAL(12,4)"),
    ("sap_llm_response_size",      "DECIMAL(14,2)"),
    ("_score",                     "DECIMAL(10,4)"),
    ("headers_http_request_method","NVARCHAR(20)"),
    ("sap_app_env",                "NVARCHAR(50)"),
    ("llm_finish_reason",          "NVARCHAR(50)"),
    ("llm_temperature",            "DECIMAL(5,2)"),
    ("llm_total_tokens",           "INTEGER"),
    ("llm_prompt",                 "NCLOB"),
]


def get_connection():
    return dbapi.connect(
        address=HANA_HOST,
        port=HANA_PORT,
        user=HANA_USER,
        password=HANA_PASS,
        encrypt=True,
        sslValidateCertificate=False
    )


def _create_table(cursor, ddl: str, table_name: str):
    try:
        cursor.execute(ddl)
        print(f"[HANA] Tabla {table_name} creada")
    except Exception as e:
        if getattr(e, 'errorcode', None) == 288 or "duplicate table name" in str(e).lower():
            print(f"[HANA] Tabla {table_name} ya existe")
        else:
            raise


def _drop_column_if_exists(cursor, table_name: str, col_name: str):
    try:
        cursor.execute(f'ALTER TABLE "{HANA_SCHEMA}"."{table_name}" DROP ("{col_name}")')
    except Exception as e:
        # Columna ya no existe — ignorar
        if getattr(e, 'errorcode', None) == 260 or "invalid column name" in str(e).lower():
            pass
        else:
            raise


def _add_column_if_missing(cursor, table_name: str, col_name: str, col_type: str):
    try:
        cursor.execute(
            f'ALTER TABLE "{HANA_SCHEMA}"."{table_name}" ADD ("{col_name}" {col_type})'
        )
    except Exception as e:
        if getattr(e, 'errorcode', None) in (308, 386) or "exist" in str(e).lower():
            pass
        else:
            raise


def create_tables_if_not_exist(conn):
    cursor = conn.cursor()

    _create_table(cursor, SYSTEM_DDL, "SYSTEM_LOGS")
    _create_table(cursor, LLM_DDL,    "LLM_LOGS")

    for col, dtype in SYSTEM_MIGRATE:
        _add_column_if_missing(cursor, "SYSTEM_LOGS", col, dtype)
    for col, dtype in LLM_MIGRATE:
        _add_column_if_missing(cursor, "LLM_LOGS", col, dtype)

    # Eliminar columna descartada de LLM_LOGS
    _drop_column_if_exists(cursor, "LLM_LOGS", "http_status_code")

    conn.commit()
    cursor.close()
    print("[HANA] Tablas verificadas/creadas correctamente")


def upsert_batch(conn, df: pd.DataFrame, table: str, columns: list):
    if df.empty:
        print(f"[HANA] No hay datos para insertar en {table}")
        return

    cursor = conn.cursor()
    cols_str     = ", ".join([f'"{c}"' for c in columns])
    placeholders = ", ".join(["?" for _ in columns])
    sql = f'UPSERT "{HANA_SCHEMA}"."{table}" ({cols_str}) VALUES ({placeholders}) WITH PRIMARY KEY'

    rows = [
        tuple(row[col] if col in df.columns and pd.notna(row.get(col)) else None for col in columns)
        for _, row in df.iterrows()
    ]

    cursor.executemany(sql, rows)
    conn.commit()
    cursor.close()
    print(f"[HANA] {len(rows)} registros insertados/actualizados en {table}")


def load_system_logs(conn, df: pd.DataFrame):
    df = df.copy()
    if "is_security_event" in df.columns:
        df["is_security_event"] = df["is_security_event"].astype(int)
    if "timestamp" in df.columns:
        df["timestamp"] = df["timestamp"].astype(str)
    upsert_batch(conn, df, "SYSTEM_LOGS", SYSTEM_COLS)


def load_llm_logs(conn, df: pd.DataFrame):
    df = df.copy()
    if "timestamp" in df.columns:
        df["timestamp"] = df["timestamp"].astype(str)
    upsert_batch(conn, df, "LLM_LOGS", LLM_COLS)
