import numpy as np
import pandas as pd

BUCKET         = "5min"
TRAINING_HOURS = 24

# Log types válidos (filtra filas corruptas)
VALID_SYS_LOGTYPES = {"INFO", "WARNING", "ERROR", "DEBUG", "AUDIT", "PERF", "SECURITY"}
VALID_LLM_LOGTYPES = {"LLM_REQUEST", "LLM_ERROR", "LLM_TIMEOUT"}


def _entropy(series: pd.Series) -> float:
    counts = series.value_counts(normalize=True)
    return float(-(counts * np.log(counts + 1e-10)).sum()) if len(counts) > 1 else 0.0


def _pct(mask: pd.Series, total: int) -> float:
    return float(mask.sum()) / total if total else 0.0


def clean_system(df: pd.DataFrame) -> pd.DataFrame:
    """Elimina filas corruptas y normaliza tipos."""
    df = df.copy()
    df = df[df["logtype"].isin(VALID_SYS_LOGTYPES)]
    df["http_status_code"] = pd.to_numeric(df["http_status_code"], errors="coerce")
    df["is_security_event"] = df["is_security_event"].map(
        {True: 1, False: 0, "true": 1, "false": 0, 1: 1, 0: 0}
    ).fillna(0).astype(int)
    df["_score"] = pd.to_numeric(df["_score"], errors="coerce").fillna(0.5)
    return df


def clean_llm(df: pd.DataFrame) -> pd.DataFrame:
    """Normaliza tipos en LLM logs."""
    df = df.copy()
    df = df[df["logtype"].isin(VALID_LLM_LOGTYPES)]
    df["llm_response_time_ms"] = pd.to_numeric(df["llm_response_time_ms"], errors="coerce")
    df["llm_cost_usd"]         = pd.to_numeric(df["llm_cost_usd"],         errors="coerce")
    df["llm_total_tokens"]     = pd.to_numeric(df["llm_total_tokens"],     errors="coerce")
    df["sap_llm_response_size"]= pd.to_numeric(df["sap_llm_response_size"],errors="coerce")
    df["_score"]               = pd.to_numeric(df["_score"],               errors="coerce").fillna(0.5)
    return df


def build_system_features(df: pd.DataFrame, bucket: str = BUCKET) -> pd.DataFrame:
    if df.empty or "timestamp" not in df.columns:
        return pd.DataFrame()

    df = clean_system(df)
    df["bucket"] = df["timestamp"].dt.floor(bucket)

    rows = []
    for b, g in df.groupby("bucket"):
        n = len(g)
        http = g["http_status_code"].dropna()
        top_ip_n = g["sourceip"].value_counts().iloc[0] if "sourceip" in g.columns and n else 0

        rows.append({
            "bucket": b,
            # — Volumen —
            "n_sys_requests":       n,
            # — IPs —
            "n_unique_ips":         g["sourceip"].nunique(),
            "top_ip_share":         top_ip_n / n,
            # — HTTP status —
            "error_rate":           _pct(http >= 400,  n),
            "client_error_rate":    _pct((http >= 400) & (http < 500), n),
            "server_error_rate":    _pct(http >= 500,  n),
            "rate_limit_rate":      _pct(http == 429,  n),   # 429 = posible DDoS
            "timeout_http_rate":    _pct(http == 408,  n),   # 408 = timeout HTTP
            # — Tipos de log —
            "pct_error_logtype":    _pct(g["logtype"] == "ERROR",    n),
            "pct_warning_logtype":  _pct(g["logtype"] == "WARNING",  n),
            "pct_security_logtype": _pct(g["logtype"] == "SECURITY", n),
            "pct_audit_logtype":    _pct(g["logtype"] == "AUDIT",    n),
            "n_unique_logtypes":    g["logtype"].nunique(),
            # — Seguridad —
            "security_event_rate":  _pct(g["is_security_event"] == 1, n),
            "n_security_events":    int(g["is_security_event"].sum()),
            # — Métodos HTTP —
            "method_entropy":       _entropy(g["headers_http_request_method"].dropna()),
            "pct_post":             _pct(g["headers_http_request_method"] == "POST",   n),
            "pct_delete":           _pct(g["headers_http_request_method"] == "DELETE", n),
            # — Score de riesgo (bajo = inusual) —
            "avg_score":            float(g["_score"].mean()),
            "min_score":            float(g["_score"].min()),
            "pct_low_score":        _pct(g["_score"] < 0.3, n),
            # — Servicios y regiones —
            "n_unique_services":    g["port_service"].nunique() if "port_service" in g.columns else 0,
            "n_unique_regions":     g["macro_region"].nunique() if "macro_region" in g.columns else 0,
            "top_region_share":     g["macro_region"].value_counts().iloc[0] / n if "macro_region" in g.columns and n else 0,
            # — Entornos —
            "pct_production":       _pct(g["sap_app_env"] == "production", n),
            "n_unique_envs":        g["sap_app_env"].nunique() if "sap_app_env" in g.columns else 0,
        })

    return pd.DataFrame(rows).set_index("bucket").sort_index()


def build_llm_features(df: pd.DataFrame, bucket: str = BUCKET) -> pd.DataFrame:
    if df.empty or "timestamp" not in df.columns:
        return pd.DataFrame()

    df = clean_llm(df)
    df["bucket"] = df["timestamp"].dt.floor(bucket)

    rows = []
    for b, g in df.groupby("bucket"):
        n    = len(g)
        lat  = g["llm_response_time_ms"].dropna()
        cost = g["llm_cost_usd"].dropna()
        tok  = g["llm_total_tokens"].dropna()

        rows.append({
            "bucket": b,
            # — Volumen —
            "n_llm_requests":      n,
            # — Éxito / error —
            "llm_error_rate":      _pct(g["logtype"] == "LLM_ERROR",   n),
            "llm_timeout_rate":    _pct(g["logtype"] == "LLM_TIMEOUT", n),
            # — Latencia —
            "avg_llm_latency":     float(lat.mean())           if len(lat) else 0,
            "p95_llm_latency":     float(lat.quantile(0.95))   if len(lat) else 0,
            "max_llm_latency":     float(lat.max())            if len(lat) else 0,
            "pct_slow_llm":        _pct(lat > 20_000, n),      # >20 s = lento
            # — Costo —
            "avg_llm_cost":        float(cost.mean())          if len(cost) else 0,
            "total_llm_cost":      float(cost.sum())           if len(cost) else 0,
            "max_llm_cost":        float(cost.max())           if len(cost) else 0,
            # — Tokens —
            "avg_tokens":          float(tok.mean())           if len(tok) else 0,
            "max_tokens":          float(tok.max())            if len(tok) else 0,
            # — Modelos —
            "n_unique_models":     g["llm_model_id"].nunique() if "llm_model_id" in g.columns else 0,
            # — Contenido sospechoso —
            "pct_content_filter":  _pct(g.get("llm_finish_reason", pd.Series()) == "content_filter", n),
            # — Score —
            "avg_llm_score":       float(g["_score"].mean()) if "_score" in g.columns else 0.5,
        })

    return pd.DataFrame(rows).set_index("bucket").sort_index()


def build_features(df_sys: pd.DataFrame, df_llm: pd.DataFrame,
                   bucket: str = BUCKET) -> pd.DataFrame:
    sys_f = build_system_features(df_sys, bucket)
    llm_f = build_llm_features(df_llm, bucket)

    combined = sys_f.join(llm_f, how="outer").fillna(0)
    n_sys = combined.get("n_sys_requests", pd.Series(0, index=combined.index))
    n_llm = combined.get("n_llm_requests", pd.Series(0, index=combined.index))
    combined["llm_to_sys_ratio"] = n_llm / (n_sys + 1)
    combined["total_requests"]   = n_sys + n_llm
    return combined
