"""
src/ml/alert_sender.py
──────────────────────
Sends detected anomaly alerts to the SAP API endpoint POST /alert.
Every attempt (sent, failed, skipped) is logged to HANA table ALERT_LOG.

Required message format (max 300 characters):
    WHAT: <what happened>. WHEN: <ISO timestamp>. WHY: <reason with key metrics>.
"""
import logging
import uuid
from datetime import datetime

import requests

from config import API_BASE_URL, HEADERS, HANA_SCHEMA

logger = logging.getLogger("ML_PIPELINE.alert")

_ALERT_URL = f"{API_BASE_URL}/alert"
_MAX_MSG   = 300


# ── HANA: tabla de auditoría de alertas ──────────────────────────────────────

def create_alert_log_table(conn) -> None:
    """
    Crea ALERT_LOG si no existe.
    Columnas:
      alert_id        — UUID único por intento
      sent_at         — timestamp del intento
      bucket_start    — ventana temporal de la anomalía
      anomaly_type    — SPIKE | MULTI_BUCKET | CATEGORIZATION
      attack_category — categoría de seguridad enviada
      severity        — HIGH | MEDIUM
      status          — SENT | FAILED
      http_status     — código HTTP recibido (NULL si error de red)
      message_sent    — texto enviado a la API (máx 300 chars)
      api_response    — respuesta truncada de la API (máx 500 chars)
    """
    cursor = conn.cursor()
    try:
        cursor.execute(f"""
            CREATE TABLE "{HANA_SCHEMA}"."ALERT_LOG" (
                "alert_id"        NVARCHAR(64)   PRIMARY KEY,
                "sent_at"         TIMESTAMP,
                "bucket_start"    NVARCHAR(30),
                "anomaly_type"    NVARCHAR(30),
                "attack_category" NVARCHAR(100),
                "severity"        NVARCHAR(10),
                "status"          NVARCHAR(10),
                "http_status"     INTEGER,
                "message_sent"    NVARCHAR(300),
                "api_response"    NVARCHAR(500)
            )
        """)
        conn.commit()
        logger.info("Tabla ALERT_LOG creada en HANA")
    except Exception as e:
        if getattr(e, "errorcode", None) == 288 or "duplicate table name" in str(e).lower():
            pass  # ya existe
        else:
            logger.warning("No se pudo crear ALERT_LOG: %s", e)
    finally:
        cursor.close()


def _insert_alert_log(conn, *,
                      bucket_start: str,
                      anomaly_type: str,
                      attack_category: str,
                      severity: str,
                      status: str,
                      http_status: int | None = None,
                      message_sent: str | None = None,
                      api_response: str | None = None) -> None:
    """Inserta una fila en ALERT_LOG. Silencia cualquier error para no interrumpir el pipeline."""
    try:
        cursor = conn.cursor()
        cursor.execute(f"""
            INSERT INTO "{HANA_SCHEMA}"."ALERT_LOG" (
                "alert_id","sent_at","bucket_start","anomaly_type",
                "attack_category","severity","status",
                "http_status","message_sent","api_response"
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            str(uuid.uuid4()),
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            str(bucket_start)[:30],
            str(anomaly_type)[:30],
            str(attack_category)[:100],
            str(severity)[:10],
            str(status)[:10],
            http_status,
            str(message_sent)[:300] if message_sent else None,
            str(api_response)[:500] if api_response else None,
        ))
        conn.commit()
        cursor.close()
    except Exception as e:
        logger.warning("[ALERT_LOG] No se pudo registrar en HANA: %s", e)


_CATEGORY_EN = {
    "DDoS / Flooding de Trafico":       "DDoS / Traffic Flooding",
    "Fuerza Bruta":                     "Brute Force",
    "Inyeccion de Prompt LLM":          "LLM Prompt Injection",
    "Sobrecarga de Servidor (5xx)":     "Server Overload (5xx)",
    "Concentracion Geografica":         "Geographic Concentration",
    "Reconocimiento / Escaneo":         "Reconnaissance / Scanning",
    "Escalada de Eventos de Seguridad": "Security Event Escalation",
    "Degradacion de Servicio LLM":      "LLM Service Degradation",
    "Costo LLM Anomalo":                "Anomalous LLM Cost",
    "Patron Estadistico Inusual":       "Unusual Statistical Pattern",
}

_LABEL_EN = {
    "Volumen de requests sistema":              "System request volume",
    "IPs únicas":                               "Unique IPs",
    "Concentración en 1 IP":                    "Top-IP concentration",
    "Tasa de errores HTTP":                     "HTTP error rate",
    "Tasa 4xx (errores cliente)":               "4xx rate (client errors)",
    "Tasa 5xx (errores servidor)":              "5xx rate (server errors)",
    "Tasa 429 (rate-limit / posible DDoS)":     "429 rate (rate-limit / DDoS)",
    "Tasa 408 (timeouts HTTP)":                 "408 rate (HTTP timeouts)",
    "% logs tipo ERROR":                        "% ERROR log type",
    "% logs tipo WARNING":                      "% WARNING log type",
    "% logs tipo SECURITY":                     "% SECURITY log type",
    "Tasa de eventos de seguridad":             "Security event rate",
    "Nº eventos de seguridad":                  "# Security events",
    "% métodos POST":                           "% POST methods",
    "% métodos DELETE":                         "% DELETE methods",
    "Score mínimo de riesgo (bajo = inusual)":  "Min risk score (low = unusual)",
    "% logs con score de riesgo bajo (<0.3)":   "% low-risk score logs (<0.3)",
    "Volumen de requests LLM":                  "LLM request volume",
    "Tasa de errores LLM":                      "LLM error rate",
    "Tasa de timeouts LLM":                     "LLM timeout rate",
    "Latencia promedio LLM (ms)":               "Avg LLM latency (ms)",
    "Latencia p95 LLM (ms)":                    "p95 LLM latency (ms)",
    "% requests LLM lentos (>20 s)":            "% slow LLM requests (>20s)",
    "Costo total LLM (USD) en ventana":         "Total LLM cost (USD) in window",
    "Costo máximo LLM en ventana (USD)":        "Max LLM cost in window (USD)",
    "% prompts con content_filter (sospechosos)": "% prompts flagged by content_filter",
    "Ratio LLM vs requests sistema":            "LLM-to-system request ratio",
    "Volumen total combinado":                  "Total combined request volume",
}


def _translate_category(category: str) -> str:
    return _CATEGORY_EN.get(category, category)


def _translate_label(label: str) -> str:
    return _LABEL_EN.get(label, label)


def _build_message(anomaly: dict) -> str:
    a_type   = anomaly.get("anomaly_type", "UNKNOWN")
    category = _translate_category(anomaly.get("attack_category", "Unusual Pattern"))
    severity = anomaly.get("severity", "?")
    bucket   = anomaly.get("bucket_start", "")

    try:
        ts = str(bucket).replace(" ", "T")
        if len(ts) == 19:
            ts += "Z"
    except Exception:
        ts = str(bucket)

    top_devs = anomaly.get("top_deviations") or []
    if top_devs:
        top   = top_devs[0]
        label = _translate_label(top["label"])
        why_detail = (
            f"{label}={top['value']:.3f} (z={top['z_score']:+.2f}, "
            f"baseline={top['baseline']:.3f})"
        )
    else:
        why_detail = "unusual statistical pattern with no dominant feature"

    n_req    = int(anomaly.get("n_requests", 0))
    err_rate = float(anomaly.get("error_rate", 0))
    top_ip   = anomaly.get("top_ip") or "N/A"

    what = f"WHAT: {category} [{a_type}] sev={severity}."
    when = f" WHEN: {ts}."
    why  = f" WHY: {why_detail}, {n_req} reqs, err={err_rate:.1%}, top_ip={top_ip}."

    msg = what + when + why
    if len(msg) > _MAX_MSG:
        budget    = _MAX_MSG - len(what) - len(when) - 1
        why_short = f" WHY: {why_detail}."
        if len(why_short) > budget:
            why_short = (" WHY: " + why_detail[:budget - 8] + "...").rstrip() + "."
        msg = what + when + why_short

    return msg[:_MAX_MSG]


def send_alert(anomaly: dict) -> dict:
    """
    Envía una alerta a POST /alert.
    Retorna dict con: ok, http_status, api_response, message.
    """
    message = _build_message(anomaly)

    logger.info(
        "[ALERT] Sending alert to %s | bucket=%s | type=%s | severity=%s",
        _ALERT_URL,
        anomaly.get("bucket_start"),
        anomaly.get("anomaly_type"),
        anomaly.get("severity"),
    )
    logger.info("[ALERT] Message (%d chars): %s", len(message), message)

    try:
        resp = requests.post(
            _ALERT_URL,
            json={"message": message},
            headers=HEADERS,
            timeout=10,
        )
        if resp.ok:
            logger.info(
                "[ALERT] OK — HTTP %s | bucket=%s | response: %s",
                resp.status_code,
                anomaly.get("bucket_start"),
                resp.text[:200],
            )
            return {"ok": True, "http_status": resp.status_code,
                    "api_response": resp.text[:500], "message": message}
        else:
            logger.warning(
                "[ALERT] FAILED — HTTP %s | bucket=%s | response: %s",
                resp.status_code,
                anomaly.get("bucket_start"),
                resp.text[:200],
            )
            return {"ok": False, "http_status": resp.status_code,
                    "api_response": resp.text[:500], "message": message}
    except requests.RequestException as exc:
        logger.error(
            "[ALERT] Network error sending alert | bucket=%s | %s",
            anomaly.get("bucket_start"),
            exc,
        )
        return {"ok": False, "http_status": None,
                "api_response": str(exc)[:500], "message": message}


# Categorías de ataque que generan alertas a la API SAP.
# Las anomalías operativas (Costo LLM, Degradación de Servicio, etc.)
# se guardan en HANA pero NO se envían como alerta.
_SECURITY_ALERT_CATEGORIES: frozenset[str] = frozenset({
    "Escalada de Eventos de Seguridad",
    "DDoS / Flooding de Trafico",
    "Fuerza Bruta",
    "Inyeccion de Prompt LLM",
    "Reconocimiento / Escaneo",
    "Concentracion Geografica",
})


def send_alerts_batch(anomalies_df, conn=None) -> dict:
    """
    Envía alertas a POST /alert solo para anomalías de seguridad HIGH o MEDIUM.

    Filtros aplicados (ambos deben cumplirse):
    · severity != LOW
    · attack_category está en _SECURITY_ALERT_CATEGORIES

    Las anomalías operativas (Degradación LLM, Costo Anómalo, etc.) se omiten
    aquí pero siguen guardándose completas en HANA sin ninguna modificación.

    Si se pasa `conn`, cada intento (SENT / FAILED / SKIPPED) queda registrado
    en la tabla HANA ALERT_LOG para auditoría.
    """
    if conn is not None:
        create_alert_log_table(conn)

    sent = failed = skipped = 0

    for _, row in anomalies_df.iterrows():
        severity = row.get("severity", "LOW")
        category = row.get("attack_category", "")
        bucket   = row.get("bucket")
        a_type   = row.get("anomaly_type", "")

        # Omitir severidad LOW
        if severity == "LOW":
            skipped += 1
            logger.debug("[ALERT] Omitida (LOW) | bucket=%s", bucket)
            continue

        # Omitir categorías no relacionadas con seguridad
        if category not in _SECURITY_ALERT_CATEGORIES:
            skipped += 1
            logger.debug(
                "[ALERT] Omitida (no es categoría de seguridad) | "
                "category=%s | bucket=%s", category, bucket,
            )
            continue

        anomaly = {
            "anomaly_type":    a_type,
            "attack_category": category,
            "severity":        severity,
            "bucket_start":    bucket,
            "top_deviations":  row.get("top_deviations") or [],
            "n_requests":      row.get("n_requests", 0),
            "error_rate":      row.get("error_rate", 0),
            "top_ip":          row.get("top_ip"),
        }

        result = send_alert(anomaly)
        if result["ok"]:
            sent += 1
            status = "SENT"
        else:
            failed += 1
            status = "FAILED"

        if conn is not None:
            _insert_alert_log(conn,
                bucket_start=str(bucket), anomaly_type=a_type,
                attack_category=category, severity=severity,
                status=status, http_status=result.get("http_status"),
                message_sent=result.get("message"),
                api_response=result.get("api_response"))

    logger.info(
        "[ALERT] Batch summary — sent: %d | failed: %d | skipped (LOW / non-security): %d",
        sent, failed, skipped,
    )
    return {"sent": sent, "failed": failed, "skipped": skipped}
