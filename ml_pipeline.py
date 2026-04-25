import json
import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

import pandas as pd
from hdbcli import dbapi

from config import HANA_HOST, HANA_PORT, HANA_USER, HANA_PASS, HANA_SCHEMA
from ml.features import build_features, BUCKET, TRAINING_HOURS, clean_system, clean_llm
from ml.detector import AnomalyDetector
from ml.streaming_detector import StreamingDetector
from ml.versioning import save_model, load_latest_model

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [ML] - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ML_PIPELINE")

SCORE_HOURS   = TRAINING_HOURS   # evaluar la misma ventana que el entrenamiento
RETRAIN_EVERY = 2    # re-entrenar IForest cada N ciclos (2 × 30 min = 1 hora)

# Backoff para polling de HANA cuando aún no hay datos nuevos
HANA_POLL_BACKOFF = [10, 30, 60]

_cycle = 0
# HST vive durante toda la sesión — aprende de forma continua sin reiniciarse.
# window_size=8 → memoria de 8 buckets reales; warmup ≈ 4 h de reloj
# (8 ingestas × 30 min entre ingestas).
_streaming = StreamingDetector(n_trees=25, height=8, window_size=8)


# ── Conexión ──────────────────────────────────────────────────────────────────
def get_conn():
    return dbapi.connect(
        address=HANA_HOST, port=HANA_PORT,
        user=HANA_USER, password=HANA_PASS,
        encrypt=True, sslValidateCertificate=False,
    )


def _latest_hana_timestamp() -> str | None:
    """Devuelve el timestamp más reciente en SYSTEM_LOGS (o LLM_LOGS si está vacío)."""
    conn = get_conn()
    try:
        cursor = conn.cursor()
        cursor.execute(f'SELECT MAX("timestamp") FROM "{HANA_SCHEMA}"."SYSTEM_LOGS"')
        row = cursor.fetchone()
        return str(row[0]) if row and row[0] else None
    except Exception:
        return None
    finally:
        conn.close()


def _wait_for_new_hana_data(last_ts: str | None) -> str:
    """
    Consulta HANA con backoff hasta detectar un timestamp más reciente que last_ts.
    Retorna el nuevo timestamp máximo cuando hay datos frescos.
    """
    delays = iter(HANA_POLL_BACKOFF)
    next_delay = HANA_POLL_BACKOFF[-1]

    while True:
        current_ts = _latest_hana_timestamp()
        if current_ts and current_ts != last_ts:
            logger.info(f"Nuevos datos en HANA detectados: {last_ts} → {current_ts}")
            return current_ts
        try:
            next_delay = next(delays)
        except StopIteration:
            pass
        logger.info(f"HANA sin datos nuevos (ultimo: {current_ts}) "
                    f"— reintento en {next_delay} s")
        time.sleep(next_delay)


# ── Tabla ANOMALIES ───────────────────────────────────────────────────────────
def create_anomaly_table(conn):
    cursor = conn.cursor()
    try:
        cursor.execute(f"""
            CREATE TABLE "{HANA_SCHEMA}"."ANOMALIES" (
                "anomaly_id"    NVARCHAR(64)  PRIMARY KEY,
                "detected_at"   TIMESTAMP,
                "bucket_start"  TIMESTAMP,
                "anomaly_type"  NVARCHAR(30),
                "severity"      NVARCHAR(10),
                "anomaly_score" DECIMAL(10,6),
                "n_requests"    INTEGER,
                "n_unique_ips"  INTEGER,
                "error_rate"    DECIMAL(10,4),
                "top_ip"        NVARCHAR(50),
                "reason"        NVARCHAR(500),
                "details_json"  NCLOB
            )
        """)
        conn.commit()
        logger.info("Tabla ANOMALIES creada")
    except Exception as e:
        if getattr(e, "errorcode", None) == 288 or "duplicate table name" in str(e).lower():
            logger.debug("Tabla ANOMALIES ya existe")
        else:
            raise
    finally:
        cursor.close()

    # Migraciones: columnas añadidas en versiones posteriores
    for col_ddl in [
        '"reason" NVARCHAR(500)',
        '"attack_category" NVARCHAR(100)',
    ]:
        cursor = conn.cursor()
        try:
            cursor.execute(f'ALTER TABLE "{HANA_SCHEMA}"."ANOMALIES" ADD ({col_ddl})')
            conn.commit()
        except Exception:
            pass
        finally:
            cursor.close()


# ── Carga de datos desde HANA ─────────────────────────────────────────────────
def load_hana_data(conn, hours: int) -> tuple[pd.DataFrame, pd.DataFrame]:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

    df_sys = pd.read_sql(f"""
        SELECT "_id","timestamp","sourceip","port_service","logtype",
               "http_status_code","is_security_event",
               "headers_http_request_method","sap_app_env",
               "macro_region","_score","event_description"
        FROM "{HANA_SCHEMA}"."SYSTEM_LOGS"
        WHERE "timestamp" >= '{since}'
    """, conn)

    df_llm = pd.read_sql(f"""
        SELECT "_id","timestamp","logtype","llm_model_id",
               "llm_cost_usd","llm_response_time_ms","llm_total_tokens",
               "llm_status","llm_finish_reason","sap_llm_response_size",
               "sap_app_env","macro_region","_score"
        FROM "{HANA_SCHEMA}"."LLM_LOGS"
        WHERE "timestamp" >= '{since}'
    """, conn)

    for df in (df_sys, df_llm):
        df.columns = [c.lower() for c in df.columns]
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")

    return df_sys, df_llm


# ── Obtener IDs de logs en un bucket ─────────────────────────────────────────
def _ids_in_bucket(df: pd.DataFrame, bucket, max_ids: int = 50) -> list[str]:
    if df.empty or "_id" not in df.columns or "timestamp" not in df.columns:
        return []
    mask = df["timestamp"].dt.floor(BUCKET) == bucket
    return df.loc[mask, "_id"].dropna().head(max_ids).tolist()


# ── Persistir anomalías ───────────────────────────────────────────────────────
def save_anomalies(conn, anomalies_df: pd.DataFrame,
                   features_df: pd.DataFrame,
                   df_sys: pd.DataFrame, df_llm: pd.DataFrame):
    if anomalies_df.empty:
        return

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    rows = []

    for _, row in anomalies_df.iterrows():
        bucket   = row["bucket"]
        feat_row = features_df.loc[bucket] if bucket in features_df.index else pd.Series(dtype=float)

        # IP más activa del bucket
        top_ip = None
        if not df_sys.empty and "sourceip" in df_sys.columns:
            mask = df_sys["timestamp"].dt.floor(BUCKET) == bucket
            grp  = df_sys[mask]
            if not grp.empty:
                top_ip = str(grp["sourceip"].value_counts().index[0])

        # IDs de logs relacionados (trazabilidad anomalía → log)
        sys_ids = _ids_in_bucket(df_sys, bucket)
        llm_ids = _ids_in_bucket(df_llm, bucket)

        details = {
            "top_deviations":    row.get("top_deviations", []),
            "sys_log_ids":       sys_ids,
            "llm_log_ids":       llm_ids,
            "feature_snapshot":  {
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


# ── Imprimir anomalía de forma legible en consola ────────────────────────────
def _log_anomaly(a: pd.Series, features_df: pd.DataFrame):
    bucket = a["bucket"]
    feat   = features_df.loc[bucket] if bucket in features_df.index else pd.Series(dtype=float)

    logger.info("")
    logger.info(f"  ┌─ [{a['severity']:6}] {a['anomaly_type']} ────────────────────")
    logger.info(f"  │  Ventana   : {bucket}  →  +5 min")
    logger.info(f"  │  Score     : {a['anomaly_score']:.4f}  (más negativo = más anómalo)")
    logger.info(f"  │  Razón     : {a['reason']}")
    logger.info(f"  │  Requests  : sys={int(feat.get('n_sys_requests',0))}  "
                f"llm={int(feat.get('n_llm_requests',0))}")
    logger.info(f"  │  IPs únicas: {int(feat.get('n_unique_ips',0))}  "
                f"top_ip_share={feat.get('top_ip_share',0):.2%}")
    logger.info(f"  │  Error HTTP: {feat.get('error_rate',0):.2%}  "
                f"(429={feat.get('rate_limit_rate',0):.2%}  "
                f"5xx={feat.get('server_error_rate',0):.2%})")
    logger.info(f"  │  Seguridad : {int(feat.get('n_security_events',0))} eventos  "
                f"({feat.get('security_event_rate',0):.2%})")
    if feat.get("n_llm_requests", 0) > 0:
        logger.info(f"  │  LLM error : {feat.get('llm_error_rate',0):.2%}  "
                    f"timeout={feat.get('llm_timeout_rate',0):.2%}  "
                    f"costo_total=${feat.get('total_llm_cost',0):.4f}")
    logger.info(f"  │  Top features desviadas:")
    for d in a.get("top_deviations", [])[:3]:
        logger.info(f"  │    · {d['label']}: {d['value']} "
                    f"(baseline={d['baseline']}, z={d['z_score']} {d['direction']})")
    logger.info(f"  └──────────────────────────────────────────────────────────")


# ── Ciclo principal ───────────────────────────────────────────────────────────
def run_ml_pipeline():
    global _cycle
    _cycle += 1
    logger.info("=" * 62)
    logger.info(f"  CICLO ML #{_cycle}  —  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    logger.info("=" * 62)

    conn = get_conn()
    try:
        create_anomaly_table(conn)

        # Cargar datos
        logger.info(f"Cargando datos de entrenamiento (últimas {TRAINING_HOURS}h)…")
        df_sys_train, df_llm_train = load_hana_data(conn, hours=TRAINING_HOURS)
        logger.info(f"Cargando datos de scoring (última {SCORE_HOURS}h)…")
        df_sys_score, df_llm_score = load_hana_data(conn, hours=SCORE_HOURS)

        logger.info(f"Datos train  — sistema: {len(df_sys_train):,}  LLM: {len(df_llm_train):,}")
        logger.info(f"Datos score  — sistema: {len(df_sys_score):,}  LLM: {len(df_llm_score):,}")

        if df_sys_train.empty and df_llm_train.empty:
            logger.warning("Sin datos en HANA — esperando próximo ciclo")
            return

        # Feature engineering
        features_train = build_features(df_sys_train, df_llm_train)
        features_score = build_features(df_sys_score, df_llm_score)

        logger.info(f"Features  — train: {len(features_train)} buckets  "
                    f"| score: {len(features_score)} buckets "
                    f"| dimensión: {features_train.shape[1]} variables")

        if features_train.shape[0] < 5:
            logger.warning(f"Muy pocos buckets de entrenamiento ({features_train.shape[0]}), saltando")
            return

        # Entrenar o cargar modelo
        detector, meta = load_latest_model()
        should_train = detector is None or (_cycle % RETRAIN_EVERY == 1)

        if should_train:
            logger.info("Entrenando Isolation Forest con todas las variables…")
            detector = AnomalyDetector(contamination=0.05, n_estimators=150)
            detector.fit(features_train)
            version = save_model(detector, {
                "training_hours":    TRAINING_HOURS,
                "training_buckets":  len(features_train),
                "n_features":        features_train.shape[1],
                "bucket_size":       BUCKET,
            })
            logger.info(f"Modelo v{version} listo — "
                        f"{len(features_train)} buckets, "
                        f"{features_train.shape[1]} features, "
                        f"contaminación=5%")
        else:
            logger.info(f"Reutilizando modelo v{meta['version']} "
                        f"(entrena de nuevo en ciclo {_cycle + (RETRAIN_EVERY - _cycle % RETRAIN_EVERY)})")

        if features_score.empty:
            logger.info("Sin datos recientes para evaluar")
            return

        # ── IForest: scoring batch contra baseline 24h ────────────────────
        scores    = detector.score(features_score)
        preds     = detector.predict(features_score)
        iforest_anomalies = set(features_score.index[preds == -1].tolist())

        # ── HST: scoring incremental (aprende y puntúa cada bucket) ──────
        hst_scores = _streaming.learn_and_score(features_score)
        hst_flags  = _streaming.flag_anomalies(hst_scores)
        hst_anomalies = set(features_score.index[hst_flags].tolist())

        warmed = _streaming.is_warmed_up
        logger.info(f"IForest  : {len(iforest_anomalies)} anomalias  "
                    f"| HST: {len(hst_anomalies)} anomalias  "
                    f"(buckets vistos por HST: {_streaming.n_learned}"
                    f"{'' if warmed else ' — calentando...'})")

        # ── Combinación: HIGH si ambos coinciden, MEDIUM si solo uno ──────
        both_agree = iforest_anomalies & hst_anomalies
        only_iforest = iforest_anomalies - hst_anomalies
        only_hst     = hst_anomalies - iforest_anomalies

        if both_agree:
            logger.info(f"  [ALTA CONFIANZA] Ambos modelos coinciden en "
                        f"{len(both_agree)} buckets: {sorted(both_agree)}")
        if only_iforest:
            logger.info(f"  [SOLO IForest]  {len(only_iforest)} buckets "
                        f"(anomalia historica, no pico reciente)")
        if only_hst and warmed:
            logger.info(f"  [SOLO HST]      {len(only_hst)} buckets "
                        f"(cambio brusco reciente, no historico)")

        all_anomaly_idx = iforest_anomalies | (hst_anomalies if warmed else set())

        if not all_anomaly_idx:
            logger.info("Todo normal en la ultima hora")
        else:
            # Clasificar solo los que IForest marcó (tiene z-scores y reason)
            if iforest_anomalies:
                iforest_df = features_score.loc[list(iforest_anomalies)]
                iforest_scores = scores.loc[list(iforest_anomalies)]
                iforest_preds  = preds.loc[list(iforest_anomalies)]
                anomalies_df = detector.classify_type(iforest_df, iforest_scores, iforest_preds)

                # Añadir flag de confirmación HST para enriquecer details_json
                anomalies_df["hst_confirmed"] = anomalies_df["bucket"].isin(both_agree)

                for _, a in anomalies_df.iterrows():
                    _log_anomaly(a, features_score)

                save_anomalies(conn, anomalies_df, features_score,
                               df_sys_score, df_llm_score)

    except Exception as e:
        logger.error(f"ERROR en ciclo ML: {e}", exc_info=True)
    finally:
        conn.close()


if __name__ == "__main__":
    # Primera ejecución con los datos que ya existen en HANA
    last_ts = _latest_hana_timestamp()
    logger.info(f"Timestamp inicial en HANA: {last_ts}")
    run_ml_pipeline()

    # Ciclos siguientes: esperar datos nuevos en HANA antes de scorear
    while True:
        last_ts = _wait_for_new_hana_data(last_ts)
        run_ml_pipeline()
