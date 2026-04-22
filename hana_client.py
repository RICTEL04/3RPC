import pandas as pd
from hdbcli import dbapi
from config import HANA_HOST, HANA_PORT, HANA_USER, HANA_PASS, HANA_SCHEMA


def get_connection():
    return dbapi.connect(
        address=HANA_HOST,
        port=HANA_PORT,
        user=HANA_USER,
        password=HANA_PASS,
        encrypt=True,
        sslValidateCertificate=False
    )


def create_tables_if_not_exist(conn):
    cursor = conn.cursor()

    # Tabla logs de sistema
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS "{HANA_SCHEMA}"."SYSTEM_LOGS" (
            "_id"               NVARCHAR(64)  PRIMARY KEY,
            "timestamp"         TIMESTAMP,
            "logtype"           NVARCHAR(20),
            "sourceip"          NVARCHAR(50),
            "http_status_code"  INTEGER,
            "event_description" NVARCHAR(500),
            "is_security_event" TINYINT,
            "raw_json"          NCLOB
        )
    """)

    # Tabla logs LLM
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS "{HANA_SCHEMA}"."LLM_LOGS" (
            "_id"                  NVARCHAR(64)  PRIMARY KEY,
            "timestamp"            TIMESTAMP,
            "logtype"              NVARCHAR(20),
            "llm_model_id"         NVARCHAR(100),
            "llm_status"           NVARCHAR(50),
            "llm_cost_usd"         DECIMAL(10,6),
            "llm_response_time_ms" INTEGER,
            "llm_total_tokens"     INTEGER,
            "raw_json"             NCLOB
        )
    """)

    conn.commit()
    cursor.close()
    print("[HANA] Tablas verificadas/creadas correctamente")


def upsert_batch(conn, df: pd.DataFrame, table: str, columns: list):
    if df.empty:
        print(f"[HANA] No hay datos para insertar en {table}")
        return

    cursor = conn.cursor()
    cols_str = ", ".join([f'"{c}"' for c in columns])
    placeholders = ", ".join(["?" for _ in columns])

    # WITH PRIMARY KEY hace upsert real: inserta o reemplaza por PK
    sql = f'UPSERT "{HANA_SCHEMA}"."{table}" ({cols_str}) VALUES ({placeholders}) WITH PRIMARY KEY'

    rows = [
        tuple(row[col] if pd.notna(row.get(col)) else None for col in columns)
        for _, row in df.iterrows()
    ]

    cursor.executemany(sql, rows)
    conn.commit()
    cursor.close()
    print(f"[HANA] {len(rows)} registros insertados/actualizados en {table}")


def load_system_logs(conn, df: pd.DataFrame):
    df = df.copy()
    df["raw_json"] = df.apply(lambda r: r.to_json(), axis=1)
    # is_security_event como entero (TINYINT)
    if "is_security_event" in df.columns:
        df["is_security_event"] = df["is_security_event"].astype(int)
    # timestamp a string compatible con HANA
    if "timestamp" in df.columns:
        df["timestamp"] = df["timestamp"].astype(str)

    columns = [
        "_id", "timestamp", "logtype", "sourceip",
        "http_status_code", "event_description",
        "is_security_event", "raw_json"
    ]
    upsert_batch(conn, df, "SYSTEM_LOGS", columns)


def load_llm_logs(conn, df: pd.DataFrame):
    df = df.copy()
    df["raw_json"] = df.apply(lambda r: r.to_json(), axis=1)
    if "timestamp" in df.columns:
        df["timestamp"] = df["timestamp"].astype(str)

    columns = [
        "_id", "timestamp", "logtype",
        "llm_model_id", "llm_status", "llm_cost_usd",
        "llm_response_time_ms", "llm_total_tokens", "raw_json"
    ]
    upsert_batch(conn, df, "LLM_LOGS", columns)
