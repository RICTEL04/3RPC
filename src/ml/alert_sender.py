"""
src/ml/alert_sender.py
──────────────────────
Sends detected anomaly alerts to the SAP API endpoint POST /alert.

Required message format (max 300 characters):
    WHAT: <what happened>. WHEN: <ISO timestamp>. WHY: <reason with key metrics>.
"""
import logging

import requests

from config import API_BASE_URL, HEADERS

logger = logging.getLogger("ML_PIPELINE.alert")

_ALERT_URL = f"{API_BASE_URL}/alert"
_MAX_MSG   = 300

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


def send_alert(anomaly: dict) -> bool:
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
            return True
        else:
            logger.warning(
                "[ALERT] FAILED — HTTP %s | bucket=%s | response: %s",
                resp.status_code,
                anomaly.get("bucket_start"),
                resp.text[:200],
            )
            return False
    except requests.RequestException as exc:
        logger.error(
            "[ALERT] Network error sending alert | bucket=%s | %s",
            anomaly.get("bucket_start"),
            exc,
        )
        return False


def send_alerts_batch(anomalies_df) -> dict:
    """
    Envía alertas para todas las anomalías en un DataFrame.
    Solo envía HIGH y MEDIUM; omite LOW para no saturar la API.
    """
    sent = failed = skipped = 0

    for _, row in anomalies_df.iterrows():
        severity = row.get("severity", "LOW")
        if severity == "LOW":
            skipped += 1
            logger.debug("[ALERT] Skipping LOW anomaly | bucket=%s", row.get("bucket"))
            continue

        anomaly = {
            "anomaly_type":    row.get("anomaly_type"),
            "attack_category": row.get("attack_category"),
            "severity":        severity,
            "bucket_start":    row.get("bucket"),
            "top_deviations":  row.get("top_deviations") or [],
            "n_requests":      row.get("n_requests", 0),
            "error_rate":      row.get("error_rate", 0),
            "top_ip":          row.get("top_ip"),
        }

        ok = send_alert(anomaly)
        if ok:
            sent += 1
        else:
            failed += 1

    logger.info(
        "[ALERT] Batch summary — sent: %d | failed: %d | skipped (LOW): %d",
        sent, failed, skipped,
    )
    return {"sent": sent, "failed": failed, "skipped": skipped}
