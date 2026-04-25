"""
verify_anomalies.py
───────────────────
Herramienta de auditoría: muestra las anomalías detectadas y los logs
reales que cayeron en cada ventana anómala, para que puedas confirmar
si el modelo está detectando correctamente.

Uso:
    python verify_anomalies.py              # últimas 24h
    python verify_anomalies.py --hours 48  # últimas 48h
    python verify_anomalies.py --top 5     # las 5 peores anomalías
"""
import argparse
import json
from datetime import datetime, timedelta, timezone

import pandas as pd
from hdbcli import dbapi

from config import HANA_HOST, HANA_PORT, HANA_USER, HANA_PASS, HANA_SCHEMA


def get_conn():
    return dbapi.connect(
        address=HANA_HOST, port=HANA_PORT,
        user=HANA_USER, password=HANA_PASS,
        encrypt=True, sslValidateCertificate=False,
    )


def load_anomalies(conn, hours: int) -> pd.DataFrame:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    df = pd.read_sql(f"""
        SELECT "anomaly_id","detected_at","bucket_start","anomaly_type",
               "severity","anomaly_score","n_requests","n_unique_ips",
               "error_rate","top_ip","reason","details_json"
        FROM "{HANA_SCHEMA}"."ANOMALIES"
        WHERE "detected_at" >= '{since}'
        ORDER BY "anomaly_score" ASC
    """, conn)
    df.columns = [c.lower() for c in df.columns]
    return df


def load_logs_in_window(conn, bucket_start: str, table: str,
                        id_list: list[str]) -> pd.DataFrame:
    if not id_list:
        return pd.DataFrame()
    ids_quoted = ", ".join([f"'{i}'" for i in id_list[:30]])
    df = pd.read_sql(f"""
        SELECT * FROM "{HANA_SCHEMA}"."{table}"
        WHERE "_id" IN ({ids_quoted})
        ORDER BY "timestamp"
    """, conn)
    df.columns = [c.lower() for c in df.columns]
    return df


def _bar(value: float, max_val: float = 1.0, width: int = 20) -> str:
    filled = int((value / max_val) * width) if max_val else 0
    return "█" * filled + "░" * (width - filled)


def print_anomaly_report(anomaly: pd.Series, sys_logs: pd.DataFrame,
                         llm_logs: pd.DataFrame, top_devs: list):
    sev_color = {"HIGH": "!!!!", "MEDIUM": "!! ", "LOW": "!  "}.get(anomaly["severity"], "   ")
    print()
    print("=" * 70)
    print(f"  {sev_color} [{anomaly['severity']}] {anomaly['anomaly_type']}")
    print(f"       Ventana  : {anomaly['bucket_start']}  (+5 min)")
    print(f"       Detectado: {anomaly['detected_at']}")
    print(f"       Score    : {anomaly['anomaly_score']:.4f}  "
          f"(más negativo = más anómalo, normal ≈ 0)")
    print(f"       Requests : {anomaly['n_requests']}  |  "
          f"IPs únicas: {anomaly['n_unique_ips']}  |  "
          f"Error HTTP: {anomaly['error_rate']:.1%}")
    if anomaly.get("top_ip"):
        print(f"       IP top   : {anomaly['top_ip']}")
    print()
    print(f"  RAZON: {anomaly['reason']}")
    print()

    # ── Features más desviadas ──────────────────────────────────────────────
    if top_devs:
        print("  FEATURES MAS DESVIADAS DEL BASELINE:")
        print(f"  {'Feature':<42} {'Valor':>8}  {'Baseline':>8}  {'Z':>6}  Barra")
        print("  " + "-" * 66)
        for d in top_devs[:6]:
            barra = _bar(abs(d["z_score"]), max_val=5)
            sign  = "+" if d["z_score"] > 0 else " "
            print(f"  {d['label']:<42} {d['value']:>8.3f}  "
                  f"{d['baseline']:>8.3f}  {sign}{d['z_score']:>5.2f}  {barra}")
        print()

    # ── Logs de sistema en esa ventana ─────────────────────────────────────
    if not sys_logs.empty:
        print(f"  LOGS DE SISTEMA EN LA VENTANA ({len(sys_logs)} mostrados):")
        cols = ["timestamp", "sourceip", "logtype", "http_status_code",
                "is_security_event", "event_description"]
        cols = [c for c in cols if c in sys_logs.columns]
        print(sys_logs[cols].to_string(index=False, max_colwidth=55))
        print()
        print("  Resumen sistema:")
        if "logtype" in sys_logs.columns:
            print(f"    Tipos de log   : {sys_logs['logtype'].value_counts().to_dict()}")
        if "http_status_code" in sys_logs.columns:
            codes = sys_logs["http_status_code"].value_counts().head(5).to_dict()
            print(f"    HTTP status    : {codes}")
        if "is_security_event" in sys_logs.columns:
            n_sec = (sys_logs["is_security_event"].isin([1, True, "true", "True"])).sum()
            print(f"    Eventos seg.   : {n_sec} de {len(sys_logs)}")
        print()

    # ── Logs LLM en esa ventana ─────────────────────────────────────────────
    if not llm_logs.empty:
        print(f"  LOGS LLM EN LA VENTANA ({len(llm_logs)} mostrados):")
        cols = ["timestamp", "logtype", "llm_model_id", "llm_status",
                "llm_response_time_ms", "llm_cost_usd", "llm_finish_reason"]
        cols = [c for c in cols if c in llm_logs.columns]
        print(llm_logs[cols].to_string(index=False, max_colwidth=40))
        print()
        print("  Resumen LLM:")
        if "logtype" in llm_logs.columns:
            print(f"    Tipos          : {llm_logs['logtype'].value_counts().to_dict()}")
        if "llm_finish_reason" in llm_logs.columns:
            print(f"    Finish reason  : {llm_logs['llm_finish_reason'].value_counts().to_dict()}")
        if "llm_cost_usd" in llm_logs.columns:
            total = llm_logs["llm_cost_usd"].sum()
            print(f"    Costo total    : ${total:.4f}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=int, default=24, help="Horas hacia atrás a revisar")
    parser.add_argument("--top",   type=int, default=10, help="Top N anomalías a mostrar")
    args = parser.parse_args()

    print(f"\nVerificando anomalías de las últimas {args.hours}h...")
    conn = get_conn()

    anomalies = load_anomalies(conn, hours=args.hours)

    if anomalies.empty:
        print("No se encontraron anomalías en ese período.")
        print("Tip: corre ml_pipeline.py primero para detectar anomalías.")
        conn.close()
        return

    print(f"Total anomalías encontradas: {len(anomalies)}")
    print(f"Mostrando las {min(args.top, len(anomalies))} más severas:\n")

    resumen = anomalies.groupby(["anomaly_type", "severity"]).size().reset_index(name="count")
    print("RESUMEN:")
    print(resumen.to_string(index=False))

    for _, row in anomalies.head(args.top).iterrows():
        details   = json.loads(row.get("details_json") or "{}")
        top_devs  = details.get("top_deviations", [])
        sys_ids   = details.get("sys_log_ids", [])
        llm_ids   = details.get("llm_log_ids", [])

        sys_logs = load_logs_in_window(conn, row["bucket_start"], "SYSTEM_LOGS", sys_ids)
        llm_logs = load_logs_in_window(conn, row["bucket_start"], "LLM_LOGS",   llm_ids)

        print_anomaly_report(row, sys_logs, llm_logs, top_devs)

    conn.close()
    print("\n" + "=" * 70)
    print("Verificacion completa.")
    print("Si una anomalia NO tiene sentido → ajusta contamination en ml_pipeline.py")
    print("Si faltan anomalias obvias       → baja contamination (ej: 0.03)")
    print("Si hay demasiadas falsas alarmas → sube contamination (ej: 0.08)")


if __name__ == "__main__":
    main()
