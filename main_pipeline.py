"""
Pipeline unificado 3RPC: ETL + ML en un solo proceso.

Flujo garantizado por ciclo:
  1. Poll /info hasta detectar ventana nueva en la API
  2. Drenar cola pendiente (datos que no llegaron a HANA en ciclos anteriores)
  3. ETL completo: fetch API → transform → CSV local → HANA
  4. ML scoring: features → IForest + HST → anomalías → HANA

Si HANA falla durante el ETL, el batch se guarda en exports/pending_queue.json
y se reintenta en el siguiente ciclo, garantizando cero pérdida de datos
mientras el proceso esté vivo (CSVs locales actúan como buffer permanente).
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pandas as pd
from hdbcli import dbapi

from config import HANA_HOST, HANA_PORT, HANA_USER, HANA_PASS, HANA_SCHEMA
from ingestion import fetch_all_logs, get_window_info
from preprocessing import build_dataframe, split_by_type, flag_security_events
from hana_client import (
    get_connection, create_tables_if_not_exist,
    load_system_logs, load_llm_logs,
)
from ml.features import build_features, BUCKET, TRAINING_HOURS
from ml.detector import AnomalyDetector
from ml.streaming_detector import StreamingDetector
from ml.versioning import save_model, load_latest_model
from heartbeat import HeartbeatThread

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [3RPC] - %(levelname)s - %(message)s",
)
logger = logging.getLogger("MAIN_PIPELINE")

# ── Configuración ETL ─────────────────────────────────────────────────────────
EXPORT_DIR   = "exports"
PENDING_FILE = os.path.join(EXPORT_DIR, "pending_queue.json")
POLL_BACKOFF = [5, 10, 30, 60]   # segundos entre reintentos de /info

# ── Configuración ML ──────────────────────────────────────────────────────────
SCORE_HOURS        = TRAINING_HOURS   # evaluar la misma ventana de entrenamiento
RETRAIN_EVERY      = 2                # re-entrenar IForest cada N ciclos completados
MIN_TRAINING_HOURS = 24               # horas mínimas de datos en HANA para activar ML

# ── Estado global de sesión ───────────────────────────────────────────────────
HST_STATE_FILE = os.path.join("models", "hst_state.pkl")
ML_STATE_FILE  = os.path.join("models", "ml_state.json")

_cycle = 0


def _save_ml_state(cycle: int, last_scored_until: str):
    """Persiste ciclo y último timestamp evaluado para sobrevivir reinicios."""
    os.makedirs("models", exist_ok=True)
    with open(ML_STATE_FILE, "w") as f:
        json.dump({
            "cycle":             cycle,
            "last_scored_until": last_scored_until,
            "saved_at":          datetime.utcnow().isoformat(),
        }, f, indent=2)


def _load_ml_state() -> tuple[int, str | None]:
    """
    Carga el estado persistido del ML.
    Retorna (cycle, last_scored_until) o (0, None) si no existe.
    """
    if not os.path.exists(ML_STATE_FILE):
        return 0, None
    try:
        with open(ML_STATE_FILE) as f:
            state = json.load(f)
        cycle             = state.get("cycle", 0)
        last_scored_until = state.get("last_scored_until")
        logger.info(
            f"Estado ML restaurado — ciclo={cycle} | "
            f"último scoring hasta: {last_scored_until}"
        )
        return cycle, last_scored_until
    except Exception as e:
        logger.warning(f"No se pudo cargar ml_state.json: {e} — iniciando desde cero")
        return 0, None


def _load_hst() -> StreamingDetector:
    """Restaura el HST desde disco si existe; si no, crea uno nuevo."""
    if os.path.exists(HST_STATE_FILE):
        try:
            import pickle
            with open(HST_STATE_FILE, "rb") as f:
                hst = pickle.load(f)
            logger.info(
                f"HST restaurado desde disco — "
                f"{hst.n_learned} buckets aprendidos previamente "
                f"({'caliente' if hst.is_warmed_up else 'calentando...'})"
            )
            return hst
        except Exception as e:
            logger.warning(f"No se pudo restaurar HST ({e}) — iniciando desde cero")
    else:
        logger.info("HST sin estado previo — iniciando desde cero")
    return StreamingDetector(n_trees=25, height=8, window_size=8)


def _save_hst(hst: StreamingDetector):
    """Persiste el estado actual del HST a disco (sobreescribe — solo 1 archivo)."""
    import pickle
    os.makedirs("models", exist_ok=True)
    with open(HST_STATE_FILE, "wb") as f:
        pickle.dump(hst, f)
    logger.info(
        f"HST guardado — {hst.n_learned} buckets aprendidos "
        f"({'caliente' if hst.is_warmed_up else 'calentando...'})"
    )


_streaming = _load_hst()
_cycle, _last_scored_until = _load_ml_state()


# ══════════════════════════════════════════════════════════════════════════════
# UTILIDADES COMUNES
# ══════════════════════════════════════════════════════════════════════════════

# Segundos de espera entre reintentos de conexión a HANA
HANA_RETRY_BACKOFF  = [15, 30, 60, 120]
# Segundos a esperar después de mandar a encender HANA antes de reintentar
HANA_BOOT_WAIT      = 180


def _trigger_hana_start():
    """
    El reinicio de HANA es responsabilidad del watchdog.py en el servidor físico.
    El pipeline solo registra el evento y confía en el retry loop para reconectar
    cuando HANA vuelva a estar disponible.
    """
    logger.warning(
        "HANA no disponible — el watchdog externo debe encenderla. "
        "El pipeline seguirá reintentando la conexión automáticamente."
    )


def _get_conn():
    return dbapi.connect(
        address=HANA_HOST, port=HANA_PORT,
        user=HANA_USER, password=HANA_PASS,
        encrypt=True, sslValidateCertificate=False,
    )


def _get_conn_with_retry() -> dbapi.Connection:
    """
    Intenta conectar a HANA con backoff.
    Si falla repetidamente, manda a encender HANA y sigue esperando.
    Nunca lanza excepción — el proceso no muere por falta de conexión.
    """
    delays        = iter(HANA_RETRY_BACKOFF)
    next_delay    = HANA_RETRY_BACKOFF[-1]
    hana_started  = False
    attempt       = 0

    while True:
        attempt += 1
        try:
            conn = _get_conn()
            if attempt > 1:
                logger.info("Conexión a HANA restaurada")
            return conn
        except Exception as e:
            try:
                next_delay = next(delays)
            except StopIteration:
                pass

            logger.error(
                f"HANA no disponible (intento #{attempt}): {e} "
                f"— reintentando en {next_delay}s"
            )

            # Al tercer intento fallido, mandar a encender HANA una sola vez
            if attempt == 3 and not hana_started:
                _trigger_hana_start()
                hana_started = True
                logger.info(f"Esperando {HANA_BOOT_WAIT}s para que HANA arranque...")
                time.sleep(HANA_BOOT_WAIT)
                continue

            time.sleep(next_delay)


def _append_csv(file_path: str, new_df: pd.DataFrame) -> int:
    """
    Append incremental a CSV local deduplicando por _id.
    Retorna el número de registros realmente nuevos añadidos.
    """
    os.makedirs(EXPORT_DIR, exist_ok=True)
    if os.path.exists(file_path):
        existing = pd.read_csv(file_path, encoding="utf-8", low_memory=False)
        before   = len(existing)
        combined = pd.concat([existing, new_df], ignore_index=True)
        combined = combined.drop_duplicates(subset=["_id"], keep="last")
        new_count = len(combined) - before
    else:
        combined  = new_df
        new_count = len(new_df)
    combined.to_csv(file_path, index=False, encoding="utf-8")
    return max(new_count, 0)


def _delete_csvs():
    """Elimina los CSVs locales cuando ya no tienen datos nuevos."""
    files = [
        os.path.join(EXPORT_DIR, "LOGS_EXPORT.csv"),
        os.path.join(EXPORT_DIR, "LOGS_SYSTEM.csv"),
        os.path.join(EXPORT_DIR, "LOGS_LLM.csv"),
    ]
    deleted = []
    for f in files:
        if os.path.exists(f):
            os.remove(f)
            deleted.append(os.path.basename(f))
    if deleted:
        logger.info(f"CSVs eliminados por inactividad: {', '.join(deleted)}")


# ══════════════════════════════════════════════════════════════════════════════
# COLA DE PENDIENTES — buffer ante caídas de HANA
# ══════════════════════════════════════════════════════════════════════════════

def _enqueue_pending(df_system: pd.DataFrame, df_llm: pd.DataFrame):
    """Guarda un batch fallido en la cola local para reintento posterior."""
    os.makedirs(EXPORT_DIR, exist_ok=True)
    queue = []
    if os.path.exists(PENDING_FILE):
        try:
            with open(PENDING_FILE) as f:
                queue = json.load(f)
        except Exception:
            queue = []

    queue.append({
        "queued_at": datetime.utcnow().isoformat(),
        "system":    df_system.to_json(orient="records", date_format="iso"),
        "llm":       df_llm.to_json(orient="records",    date_format="iso"),
    })
    with open(PENDING_FILE, "w") as f:
        json.dump(queue, f)
    logger.warning(f"Batch guardado en cola local ({len(queue)} pendientes)")


def _drain_pending_queue(conn):
    """Intenta subir a HANA todos los batches pendientes de ciclos anteriores."""
    if not os.path.exists(PENDING_FILE):
        return

    try:
        with open(PENDING_FILE) as f:
            queue = json.load(f)
    except Exception:
        return

    if not queue:
        return

    logger.info(f"Drenando cola de pendientes: {len(queue)} batches...")
    failed = []
    for item in queue:
        try:
            df_sys = pd.read_json(item["system"], orient="records")
            df_llm = pd.read_json(item["llm"],    orient="records")
            load_system_logs(conn, df_sys)
            load_llm_logs(conn, df_llm)
            logger.info(f"  Batch del {item['queued_at']} recuperado OK")
        except Exception as e:
            logger.error(f"  No se pudo recuperar batch del {item['queued_at']}: {e}")
            failed.append(item)

    if failed:
        with open(PENDING_FILE, "w") as f:
            json.dump(failed, f)
    else:
        os.remove(PENDING_FILE)
        logger.info("Cola de pendientes drenada completamente")


# ══════════════════════════════════════════════════════════════════════════════
# RECOVERY AL ARRANQUE — resubir CSVs locales si HANA estuvo caída
# ══════════════════════════════════════════════════════════════════════════════

def startup_recovery(conn):
    """
    Al arrancar, re-sube los CSVs locales a HANA via UPSERT.
    Idempotente: no crea duplicados gracias a UPSERT WITH PRIMARY KEY.
    Recupera cualquier dato perdido durante caídas previas.
    """
    csv_system = os.path.join(EXPORT_DIR, "LOGS_SYSTEM.csv")
    csv_llm    = os.path.join(EXPORT_DIR, "LOGS_LLM.csv")

    recovered = 0
    for csv_path, loader, label in [
        (csv_system, load_system_logs, "SYSTEM"),
        (csv_llm,    load_llm_logs,    "LLM"),
    ]:
        if not os.path.exists(csv_path):
            continue
        try:
            df = pd.read_csv(csv_path, encoding="utf-8", low_memory=False)
            if df.empty:
                continue
            logger.info(f"Recovery: subiendo {len(df):,} registros de {label} desde CSV local...")
            loader(conn, df)
            recovered += len(df)
        except Exception as e:
            logger.error(f"Recovery fallida para {label}: {e}")

    if recovered:
        logger.info(f"Recovery completa: {recovered:,} registros verificados en HANA")
    else:
        logger.info("Recovery: CSVs vacíos o no encontrados, nada que recuperar")


# ══════════════════════════════════════════════════════════════════════════════
# POLLING DE /info — esperar ventana nueva
# ══════════════════════════════════════════════════════════════════════════════

def _sleep_until_next_slot():
    """
    Duerme hasta el próximo :00 o :30 exacto.
    Se llama tras un ciclo exitoso para no consultar la API antes de que
    la ventana pueda haber cambiado.
    """
    now = datetime.now()
    if now.minute < 30:
        target = now.replace(minute=30, second=0, microsecond=0)
    else:
        target = (now + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)

    wait = max((target - datetime.now()).total_seconds(), 0)
    logger.info(
        f"Ciclo completado — próxima ventana API a las "
        f"{target.strftime('%H:%M')}  (durmiendo {wait/60:.1f} min)"
    )
    time.sleep(wait)


def _wait_for_new_window(last_window_start: str | None) -> dict:
    """
    Consulta /info con backoff hasta detectar que window_start cambió.
    Retorna el nuevo dict de info cuando hay ventana nueva.
    """
    delays    = iter(POLL_BACKOFF)
    cur_delay = POLL_BACKOFF[-1]

    while True:
        try:
            info = get_window_info()
            if info["window_start"] != last_window_start:
                logger.info(
                    f"Nueva ventana API: {last_window_start} → {info['window_start']}  "
                    f"({info['total_records']:,} registros, {info['total_pages']} páginas)"
                )
                return info
            try:
                cur_delay = next(delays)
            except StopIteration:
                pass
            logger.info(
                f"API sin cambios (ventana: {info['window_start']}) "
                f"— reintento en {cur_delay} s"
            )
            time.sleep(cur_delay)
        except Exception as e:
            logger.error(f"Error consultando /info: {e} — reintento en 30 s")
            time.sleep(30)


# ══════════════════════════════════════════════════════════════════════════════
# FASE ETL
# ══════════════════════════════════════════════════════════════════════════════

def run_etl(conn) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Descarga la ventana activa de la API, transforma, guarda en CSV y sube a HANA.
    Si HANA falla, encola localmente para reintento.
    Retorna (df_system, df_llm) para uso inmediato del ML.
    """
    logger.info("─" * 62)
    logger.info("FASE 1/2 — ETL")
    logger.info("─" * 62)

    # 1. Extract
    records, window_info = fetch_all_logs()

    # 2. Transform
    df          = build_dataframe(records)
    df_system, df_llm = split_by_type(df)
    df_system   = flag_security_events(df_system)
    df_llm      = df_llm.drop(columns=["sourceip", "http_status_code"], errors="ignore")
    llm_cols    = [c for c in df_system.columns if "llm" in c.lower()]
    df_system   = df_system.drop(columns=llm_cols, errors="ignore")

    logger.info(
        f"Transformación: {len(df_system):,} sistema | {len(df_llm):,} LLM"
    )

    # 3. CSV local (buffer permanente ante caídas)
    new_total  = _append_csv(os.path.join(EXPORT_DIR, "LOGS_EXPORT.csv"),  df)
    new_system = _append_csv(os.path.join(EXPORT_DIR, "LOGS_SYSTEM.csv"),  df_system)
    new_llm    = _append_csv(os.path.join(EXPORT_DIR, "LOGS_LLM.csv"),     df_llm)
    new_records = new_system + new_llm
    logger.info(f"CSVs locales — registros nuevos: {new_system} sistema | {new_llm} LLM")

    # 4. HANA upload
    try:
        create_tables_if_not_exist(conn)
        _drain_pending_queue(conn)
        load_system_logs(conn, df_system)
        load_llm_logs(conn, df_llm)
        logger.info(
            f"HANA actualizado — ventana: {window_info['window_start']} "
            f"→ {window_info['window_end']}"
        )
    except Exception as e:
        logger.error(f"Fallo al subir a HANA: {e}")
        _enqueue_pending(df_system, df_llm)
        logger.warning("Datos encolados localmente — se reintentará en el próximo ciclo")

    return df_system, df_llm, new_records


# ══════════════════════════════════════════════════════════════════════════════
# ANOMALÍAS — tabla y persistencia
# ══════════════════════════════════════════════════════════════════════════════

def _create_anomaly_table(conn):
    cursor = conn.cursor()
    try:
        cursor.execute(f"""
            CREATE TABLE "{HANA_SCHEMA}"."ANOMALIES" (
                "anomaly_id"      NVARCHAR(64)  PRIMARY KEY,
                "detected_at"     TIMESTAMP,
                "bucket_start"    TIMESTAMP,
                "anomaly_type"    NVARCHAR(30),
                "severity"        NVARCHAR(10),
                "anomaly_score"   DECIMAL(10,6),
                "n_requests"      INTEGER,
                "n_unique_ips"    INTEGER,
                "error_rate"      DECIMAL(10,4),
                "top_ip"          NVARCHAR(50),
                "reason"          NVARCHAR(500),
                "details_json"    NCLOB,
                "attack_category" NVARCHAR(100)
            )
        """)
        conn.commit()
        logger.info("Tabla ANOMALIES creada")
    except Exception as e:
        if getattr(e, "errorcode", None) == 288 or "duplicate table name" in str(e).lower():
            pass
        else:
            raise
    finally:
        cursor.close()

    # Migraciones incrementales
    for col_ddl in ['"reason" NVARCHAR(500)', '"attack_category" NVARCHAR(100)']:
        cursor = conn.cursor()
        try:
            cursor.execute(
                f'ALTER TABLE "{HANA_SCHEMA}"."ANOMALIES" ADD ({col_ddl})'
            )
            conn.commit()
        except Exception:
            pass
        finally:
            cursor.close()


def _ids_in_bucket(df: pd.DataFrame, bucket, max_ids: int = 50) -> list[str]:
    if df.empty or "_id" not in df.columns or "timestamp" not in df.columns:
        return []
    mask = df["timestamp"].dt.floor(BUCKET) == bucket
    return df.loc[mask, "_id"].dropna().head(max_ids).tolist()


def _save_anomalies(conn, anomalies_df: pd.DataFrame,
                    features_df: pd.DataFrame,
                    df_sys: pd.DataFrame, df_llm: pd.DataFrame):
    if anomalies_df.empty:
        return

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    rows = []

    for _, row in anomalies_df.iterrows():
        bucket   = row["bucket"]
        feat_row = (
            features_df.loc[bucket]
            if bucket in features_df.index
            else pd.Series(dtype=float)
        )

        top_ip = None
        if not df_sys.empty and "sourceip" in df_sys.columns:
            mask = df_sys["timestamp"].dt.floor(BUCKET) == bucket
            grp  = df_sys[mask]
            if not grp.empty:
                top_ip = str(grp["sourceip"].value_counts().index[0])

        details = {
            "top_deviations":   row.get("top_deviations", []),
            "sys_log_ids":      _ids_in_bucket(df_sys, bucket),
            "llm_log_ids":      _ids_in_bucket(df_llm, bucket),
            "feature_snapshot": {
                k: round(float(v), 4) if pd.notna(v) else None
                for k, v in feat_row.items()
            },
        }

        rows.append((
            str(uuid.uuid4()),
            now_str,
            str(bucket),
            row["anomaly_type"],
            row["severity"],
            float(row["anomaly_score"]),
            int(feat_row.get("n_sys_requests", 0)),
            int(feat_row.get("n_unique_ips",   0)),
            float(feat_row.get("error_rate",   0)),
            top_ip,
            str(row.get("reason", ""))[:500],
            json.dumps(details),
            str(row.get("attack_category", ""))[:100],
        ))

    cursor = conn.cursor()
    cursor.executemany(f"""
        UPSERT "{HANA_SCHEMA}"."ANOMALIES" (
            "anomaly_id","detected_at","bucket_start","anomaly_type","severity",
            "anomaly_score","n_requests","n_unique_ips","error_rate","top_ip",
            "reason","details_json","attack_category"
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) WITH PRIMARY KEY
    """, rows)
    conn.commit()
    cursor.close()
    logger.info(f"  → {len(rows)} anomalías guardadas en HANA")


def _log_anomaly(a: pd.Series, features_df: pd.DataFrame):
    bucket = a["bucket"]
    feat   = (
        features_df.loc[bucket]
        if bucket in features_df.index
        else pd.Series(dtype=float)
    )
    logger.info("")
    logger.info(f"  [{a['severity']:6}] {a['anomaly_type']} — {a.get('attack_category','')}")
    logger.info(f"  Ventana   : {bucket}  →  +5 min")
    logger.info(f"  Score     : {a['anomaly_score']:.4f}")
    logger.info(f"  Razon     : {a['reason']}")
    logger.info(
        f"  Requests  : sys={int(feat.get('n_sys_requests', 0))}  "
        f"llm={int(feat.get('n_llm_requests', 0))}"
    )
    for d in a.get("top_deviations", [])[:3]:
        logger.info(
            f"    · {d['label']}: {d['value']} "
            f"(baseline={d['baseline']}, z={d['z_score']} {d['direction']})"
        )


# ══════════════════════════════════════════════════════════════════════════════
# FASE ML
# ══════════════════════════════════════════════════════════════════════════════

def run_ml(conn, df_sys_fresh: pd.DataFrame, df_llm_fresh: pd.DataFrame,
           last_scored_until: str | None = None):
    """
    Scoring e IForest + HST usando datos frescos recién ingestados.
    df_sys_fresh / df_llm_fresh vienen directamente del ETL del mismo ciclo.
    """
    global _cycle, _last_scored_until
    _cycle += 1
    logger.info("─" * 62)
    logger.info(f"FASE 2/2 — ML  (ciclo #{_cycle})")
    logger.info("─" * 62)

    _create_anomaly_table(conn)

    # ── Verificar que hay suficientes datos históricos en HANA ────────────────
    try:
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT MIN("timestamp"), MAX("timestamp"), COUNT(*)
            FROM "{HANA_SCHEMA}"."SYSTEM_LOGS"
        """)
        row = cursor.fetchone()
        cursor.close()

        min_ts, max_ts, total_rows = row
        if min_ts is None or max_ts is None or total_rows == 0:
            logger.info("ML en espera: HANA no tiene datos aún")
            return

        data_span_hours = (max_ts - min_ts).total_seconds() / 3600
        pct = min(data_span_hours / MIN_TRAINING_HOURS * 100, 100)
        logger.info(
            f"Datos disponibles: {data_span_hours:.1f}h de {MIN_TRAINING_HOURS}h "
            f"requeridas  [{int(pct):>3}%] {'█' * int(pct // 5)}{'░' * (20 - int(pct // 5))}"
        )

        if data_span_hours < MIN_TRAINING_HOURS:
            horas_faltan = MIN_TRAINING_HOURS - data_span_hours
            logger.info(
                f"ML en espera: faltan ~{horas_faltan:.1f}h de datos "
                f"(~{int(horas_faltan * 2)} ciclos de ingesta)"
            )
            return

    except Exception as e:
        logger.error(f"Error verificando datos en HANA: {e}")
        return

    # Cargar ventana de entrenamiento completa desde HANA
    since = (
        datetime.now(timezone.utc) - timedelta(hours=TRAINING_HOURS)
    ).strftime("%Y-%m-%d %H:%M:%S")

    df_sys_train = pd.read_sql(f"""
        SELECT "_id","timestamp","sourceip","port_service","logtype",
               "http_status_code","is_security_event",
               "headers_http_request_method","sap_app_env",
               "macro_region","_score","event_description"
        FROM "{HANA_SCHEMA}"."SYSTEM_LOGS"
        WHERE "timestamp" >= '{since}'
    """, conn)

    df_llm_train = pd.read_sql(f"""
        SELECT "_id","timestamp","logtype","llm_model_id",
               "llm_cost_usd","llm_response_time_ms","llm_total_tokens",
               "llm_status","llm_finish_reason","sap_llm_response_size",
               "sap_app_env","macro_region","_score"
        FROM "{HANA_SCHEMA}"."LLM_LOGS"
        WHERE "timestamp" >= '{since}'
    """, conn)

    for df in (df_sys_train, df_llm_train):
        df.columns = [c.lower() for c in df.columns]
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

    if df_sys_train.empty and df_llm_train.empty:
        logger.warning("Sin datos en HANA — saltando ML")
        return

    # Rango real de datos de entrenamiento
    all_train_ts = pd.concat([
        df_sys_train["timestamp"].dropna(),
        df_llm_train["timestamp"].dropna(),
    ])
    train_min = all_train_ts.min()
    train_max = all_train_ts.max()
    train_span = (train_max - train_min).total_seconds() / 3600

    logger.info(
        f"ENTRENAMIENTO — {len(df_sys_train):,} sys + {len(df_llm_train):,} LLM  "
        f"| Rango: {train_min.strftime('%Y-%m-%d %H:%M')} UTC "
        f"→ {train_max.strftime('%Y-%m-%d %H:%M')} UTC  "
        f"({train_span:.1f}h)"
    )

    # Normalizar timestamps en datos frescos del ETL
    for df in (df_sys_fresh, df_llm_fresh):
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

    # ── Catchup: si el modelo estuvo inactivo, cargar datos perdidos ──────────
    if last_scored_until:
        try:
            last_ts = pd.to_datetime(last_scored_until, utc=True)
            # Timestamps máximos en los datos frescos
            fresh_ts = pd.concat([
                df_sys_fresh["timestamp"].dropna() if "timestamp" in df_sys_fresh.columns else pd.Series(dtype="datetime64[ns, UTC]"),
                df_llm_fresh["timestamp"].dropna() if "timestamp" in df_llm_fresh.columns else pd.Series(dtype="datetime64[ns, UTC]"),
            ])
            if not fresh_ts.empty:
                fresh_min = fresh_ts.min()
                gap_hours = (fresh_min - last_ts).total_seconds() / 3600
                if gap_hours > 0.6:  # más de 36 min sin evaluar → hay datos perdidos
                    logger.info(
                        f"Catchup detectado: gap de {gap_hours:.1f}h sin scoring "
                        f"({last_ts.strftime('%H:%M')} → {fresh_min.strftime('%H:%M')} UTC) "
                        f"— cargando datos intermedios desde HANA..."
                    )
                    catchup_since = last_ts.strftime("%Y-%m-%d %H:%M:%S")
                    df_sys_catchup = pd.read_sql(f"""
                        SELECT "_id","timestamp","sourceip","port_service","logtype",
                               "http_status_code","is_security_event",
                               "headers_http_request_method","sap_app_env",
                               "macro_region","_score","event_description"
                        FROM "{HANA_SCHEMA}"."SYSTEM_LOGS"
                        WHERE "timestamp" > '{catchup_since}'
                    """, conn)
                    df_llm_catchup = pd.read_sql(f"""
                        SELECT "_id","timestamp","logtype","llm_model_id",
                               "llm_cost_usd","llm_response_time_ms","llm_total_tokens",
                               "llm_status","llm_finish_reason","sap_llm_response_size",
                               "sap_app_env","macro_region","_score"
                        FROM "{HANA_SCHEMA}"."LLM_LOGS"
                        WHERE "timestamp" > '{catchup_since}'
                    """, conn)
                    for df in (df_sys_catchup, df_llm_catchup):
                        df.columns = [c.lower() for c in df.columns]
                        if "timestamp" in df.columns:
                            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
                    # Reemplazar datos frescos con el rango completo de catchup
                    df_sys_fresh = df_sys_catchup
                    df_llm_fresh = df_llm_catchup
                    logger.info(
                        f"Catchup cargado: {len(df_sys_fresh):,} sys + "
                        f"{len(df_llm_fresh):,} LLM desde {last_ts.strftime('%Y-%m-%d %H:%M')} UTC"
                    )
        except Exception as e:
            logger.warning(f"Catchup fallido, usando solo datos frescos: {e}")

    # Rango real de datos de scoring (ventana fresca del ETL)
    all_score_ts = pd.concat([
        df_sys_fresh["timestamp"].dropna() if "timestamp" in df_sys_fresh.columns else pd.Series(dtype="datetime64[ns, UTC]"),
        df_llm_fresh["timestamp"].dropna() if "timestamp" in df_llm_fresh.columns else pd.Series(dtype="datetime64[ns, UTC]"),
    ])
    if not all_score_ts.empty:
        score_min  = all_score_ts.min()
        score_max  = all_score_ts.max()
        score_span = (score_max - score_min).total_seconds() / 60
        logger.info(
            f"SCORING     — {len(df_sys_fresh):,} sys + {len(df_llm_fresh):,} LLM  "
            f"| Rango: {score_min.strftime('%Y-%m-%d %H:%M')} UTC "
            f"→ {score_max.strftime('%Y-%m-%d %H:%M')} UTC  "
            f"({score_span:.0f} min)"
        )

    # Feature engineering
    features_train = build_features(df_sys_train,  df_llm_train)
    features_score = build_features(df_sys_fresh,   df_llm_fresh)

    logger.info(
        f"Features — train: {len(features_train)} buckets "
        f"[{features_train.index.min().strftime('%H:%M')} → "
        f"{features_train.index.max().strftime('%H:%M')} UTC]  "
        f"| score: {len(features_score)} buckets "
        f"[{features_score.index.min().strftime('%H:%M') if not features_score.empty else 'N/A'} → "
        f"{features_score.index.max().strftime('%H:%M') if not features_score.empty else 'N/A'} UTC]  "
        f"| dim: {features_train.shape[1]} variables"
    )

    # Entrenar o reutilizar IForest
    detector, meta = load_latest_model()
    should_train   = detector is None or (_cycle % RETRAIN_EVERY == 1)

    if should_train:
        logger.info("Entrenando Isolation Forest...")
        detector = AnomalyDetector(contamination=0.05, n_estimators=150)
        detector.fit(features_train)
        version = save_model(detector, {
            "training_hours":   TRAINING_HOURS,
            "training_buckets": len(features_train),
            "n_features":       features_train.shape[1],
            "bucket_size":      BUCKET,
        })
        logger.info(
            f"Modelo v{version} — {len(features_train)} buckets, "
            f"{features_train.shape[1]} features"
        )
    else:
        logger.info(
            f"Reutilizando modelo v{meta['version']} "
            f"(re-entrena en ciclo {_cycle + (RETRAIN_EVERY - _cycle % RETRAIN_EVERY)})"
        )

    if features_score.empty:
        logger.info("Sin datos frescos para evaluar")
        return

    # IForest scoring
    scores = detector.score(features_score)
    preds  = detector.predict(features_score)
    iforest_anomalies = set(features_score.index[preds == -1].tolist())

    # HST scoring
    hst_scores    = _streaming.learn_and_score(features_score)
    hst_flags     = _streaming.flag_anomalies(hst_scores)
    hst_anomalies = set(features_score.index[hst_flags].tolist())

    warmed = _streaming.is_warmed_up
    logger.info(
        f"IForest: {len(iforest_anomalies)} anomalías | "
        f"HST: {len(hst_anomalies)} anomalías "
        f"(buckets vistos: {_streaming.n_learned}"
        f"{'' if warmed else ' — calentando...'})"
    )

    both_agree   = iforest_anomalies & hst_anomalies
    only_iforest = iforest_anomalies - hst_anomalies
    only_hst     = hst_anomalies - iforest_anomalies

    if both_agree:
        logger.info(f"  [ALTA CONFIANZA] Ambos modelos: {len(both_agree)} buckets")
    if only_iforest:
        logger.info(f"  [SOLO IForest]   {len(only_iforest)} buckets")
    if only_hst and warmed:
        logger.info(f"  [SOLO HST]       {len(only_hst)} buckets")

    all_anomaly_idx = iforest_anomalies | (hst_anomalies if warmed else set())

    if not all_anomaly_idx:
        logger.info("Todo normal en los datos frescos")
    elif iforest_anomalies:
        iforest_df     = features_score.loc[list(iforest_anomalies)]
        iforest_scores = scores.loc[list(iforest_anomalies)]
        iforest_preds  = preds.loc[list(iforest_anomalies)]
        anomalies_df   = detector.classify_type(iforest_df, iforest_scores, iforest_preds)
        anomalies_df["hst_confirmed"] = anomalies_df["bucket"].isin(both_agree)

        for _, a in anomalies_df.iterrows():
            _log_anomaly(a, features_score)

        _save_anomalies(conn, anomalies_df, features_score, df_sys_fresh, df_llm_fresh)

    # Persistir HST y estado ML siempre que se haga scoring (con o sin anomalías)
    _save_hst(_streaming)
    _last_scored_until = str(features_score.index.max())
    _save_ml_state(_cycle, _last_scored_until)
    logger.info(f"  Estado ML guardado — ciclo={_cycle} | last_scored_until={_last_scored_until}")


# ══════════════════════════════════════════════════════════════════════════════
# CICLO PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def run_cycle(conn, window_info: dict) -> int:
    """
    Ejecuta un ciclo completo ETL → ML.
    Retorna el número de registros nuevos añadidos a los CSVs.
    """
    logger.info("=" * 62)
    logger.info(
        f"CICLO #{_cycle + 1}  —  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
    )
    logger.info(
        f"Ventana: {window_info['window_start']} → {window_info['window_end']}"
    )
    logger.info("=" * 62)

    try:
        df_sys, df_llm, new_records = run_etl(conn)
        run_ml(conn, df_sys, df_llm, last_scored_until=_last_scored_until)
        return new_records
    except Exception as e:
        logger.error(f"ERROR en ciclo: {e}", exc_info=True)
        return 0


if __name__ == "__main__":
    logger.info("=" * 62)
    logger.info("  3RPC MAIN PIPELINE  —  iniciando")
    logger.info("=" * 62)

    # Heartbeat daemon — manda pulso a HANA cada 60 s
    hb = HeartbeatThread()
    hb.start()

    last_window = None

    # Loop externo: si hay un error inesperado, reconecta y continúa
    while True:
        conn = None
        try:
            # Conexión con retry automático + arranque de HANA si está caída
            logger.info("Conectando a HANA...")
            conn = _get_conn_with_retry()

            create_tables_if_not_exist(conn)
            startup_recovery(conn)

            # Ventana inicial solo en el primer arranque
            empty_cycles = 0   # ciclos consecutivos sin datos nuevos

            if last_window is None:
                try:
                    initial_info = get_window_info()
                    last_window  = initial_info["window_start"]
                    logger.info(f"Ventana inicial: {last_window} — ejecutando primer ciclo...")
                    hb.set_state(_cycle, last_window, "RUNNING")
                    new_records = run_cycle(conn, initial_info)
                    hb.set_state(_cycle, last_window, "RUNNING")
                    empty_cycles = 0 if new_records > 0 else 1
                except Exception as e:
                    logger.error(f"Error en primer ciclo: {e}")
                    hb.set_error()

            # Loop principal
            while True:
                _sleep_until_next_slot()
                new_info    = _wait_for_new_window(last_window)
                last_window = new_info["window_start"]
                hb.set_state(_cycle, last_window, "RUNNING")
                new_records = run_cycle(conn, new_info)
                hb.set_state(_cycle, last_window, "RUNNING")

                # Gestión de CSVs — eliminar si 2 ciclos consecutivos sin datos nuevos
                if new_records == 0:
                    empty_cycles += 1
                    logger.info(
                        f"Sin datos nuevos en CSVs — ciclo vacío #{empty_cycles}/2"
                    )
                    if empty_cycles >= 2:
                        _delete_csvs()
                        empty_cycles = 0
                else:
                    empty_cycles = 0

        except KeyboardInterrupt:
            logger.info("Pipeline detenido manualmente")
            break
        except Exception as e:
            logger.error(
                f"Error inesperado — reconectando en 30s: {e}", exc_info=True
            )
            hb.set_error()
            time.sleep(30)
            # El loop externo vuelve a intentar _get_conn_with_retry()
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
