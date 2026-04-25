import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLS = [
    # Sistema — volumen e IPs
    "n_sys_requests", "n_unique_ips", "top_ip_share",
    # Sistema — HTTP status
    "error_rate", "client_error_rate", "server_error_rate",
    "rate_limit_rate", "timeout_http_rate",
    # Sistema — tipos de log
    "pct_error_logtype", "pct_warning_logtype", "pct_security_logtype",
    "pct_audit_logtype", "n_unique_logtypes",
    # Sistema — seguridad
    "security_event_rate", "n_security_events",
    # Sistema — métodos
    "method_entropy", "pct_post", "pct_delete",
    # Sistema — score de riesgo
    "avg_score", "min_score", "pct_low_score",
    # Sistema — geografía y entorno
    "n_unique_services", "n_unique_regions", "top_region_share",
    "pct_production", "n_unique_envs",
    # LLM — volumen y errores
    "n_llm_requests", "llm_error_rate", "llm_timeout_rate",
    # LLM — rendimiento
    "avg_llm_latency", "p95_llm_latency", "max_llm_latency", "pct_slow_llm",
    # LLM — costo y tokens
    "avg_llm_cost", "total_llm_cost", "max_llm_cost", "avg_tokens", "max_tokens",
    # LLM — modelos y contenido
    "n_unique_models", "pct_content_filter", "avg_llm_score",
    # Combinadas
    "llm_to_sys_ratio", "total_requests",
]

# Umbrales para clasificar tipo de anomalía
SPIKE_SIGMA      = 2.5  # desviaciones sobre la media → SPIKE
MULTI_BUCKET_N   = 3    # buckets consecutivos mínimos → MULTI_BUCKET
MULTI_BUCKET_GAP = 10   # gap máximo en minutos entre buckets consecutivos

# Nombres amigables para las features (para logs y dashboard)
FEATURE_LABELS = {
    "n_sys_requests":       "Volumen de requests sistema",
    "n_unique_ips":         "IPs únicas",
    "top_ip_share":         "Concentración en 1 IP",
    "error_rate":           "Tasa de errores HTTP",
    "client_error_rate":    "Tasa 4xx (errores cliente)",
    "server_error_rate":    "Tasa 5xx (errores servidor)",
    "rate_limit_rate":      "Tasa 429 (rate-limit / posible DDoS)",
    "timeout_http_rate":    "Tasa 408 (timeouts HTTP)",
    "pct_error_logtype":    "% logs tipo ERROR",
    "pct_warning_logtype":  "% logs tipo WARNING",
    "pct_security_logtype": "% logs tipo SECURITY",
    "security_event_rate":  "Tasa de eventos de seguridad",
    "n_security_events":    "Nº eventos de seguridad",
    "pct_post":             "% métodos POST",
    "pct_delete":           "% métodos DELETE",
    "min_score":            "Score mínimo de riesgo (bajo = inusual)",
    "pct_low_score":        "% logs con score de riesgo bajo (<0.3)",
    "n_llm_requests":       "Volumen de requests LLM",
    "llm_error_rate":       "Tasa de errores LLM",
    "llm_timeout_rate":     "Tasa de timeouts LLM",
    "avg_llm_latency":      "Latencia promedio LLM (ms)",
    "p95_llm_latency":      "Latencia p95 LLM (ms)",
    "pct_slow_llm":         "% requests LLM lentos (>20 s)",
    "total_llm_cost":       "Costo total LLM (USD) en ventana",
    "max_llm_cost":         "Costo máximo LLM en ventana (USD)",
    "pct_content_filter":   "% prompts con content_filter (sospechosos)",
    "llm_to_sys_ratio":     "Ratio LLM vs requests sistema",
    "total_requests":       "Volumen total combinado",
}


# ── Categorías de ataque ──────────────────────────────────────────────────────
ATTACK_RULES: list[tuple[str, dict]] = [
    # (category_name, {feature: weight})  — weighted sum of z-scores decides winner
    ("DDoS / Flooding de Trafico",       {"rate_limit_rate": 4, "n_sys_requests": 2,
                                          "top_ip_share": 1, "total_requests": 1}),
    ("Fuerza Bruta",                     {"client_error_rate": 3, "n_unique_ips": 2,
                                          "security_event_rate": 2, "pct_security_logtype": 1}),
    ("Inyeccion de Prompt LLM",          {"pct_content_filter": 5, "llm_error_rate": 2,
                                          "n_llm_requests": 1}),
    ("Sobrecarga de Servidor (5xx)",     {"server_error_rate": 4, "timeout_http_rate": 2,
                                          "pct_error_logtype": 1}),
    ("Concentracion Geografica",         {"top_region_share": 4, "n_unique_regions": -2,
                                          "top_ip_share": 1}),
    ("Reconocimiento / Escaneo",         {"method_entropy": 3, "pct_delete": 3,
                                          "n_unique_ips": 2, "n_unique_services": 1}),
    ("Escalada de Eventos de Seguridad", {"security_event_rate": 4, "n_security_events": 3,
                                          "pct_security_logtype": 2}),
    ("Degradacion de Servicio LLM",      {"llm_timeout_rate": 3, "pct_slow_llm": 3,
                                          "avg_llm_latency": 2, "p95_llm_latency": 1}),
    ("Costo LLM Anomalo",                {"total_llm_cost": 4, "max_llm_cost": 3,
                                          "avg_llm_cost": 2, "avg_tokens": 1}),
]
ATTACK_MIN_SCORE = 1.0   # if best score < this, return generic label


def classify_attack_type(top_devs: list[dict]) -> str:
    """
    Dado el listado de top deviaciones (feature, z_score), retorna la
    categoria de ataque mas probable segun reglas ponderadas por z-score.
    """
    feat_z = {d["feature"]: d["z_score"] for d in top_devs}

    best_name  = "Patron Estadistico Inusual"
    best_score = ATTACK_MIN_SCORE

    for name, weights in ATTACK_RULES:
        score = sum(feat_z.get(feat, 0.0) * w for feat, w in weights.items())
        if score > best_score:
            best_score = score
            best_name  = name

    return best_name


class AnomalyDetector:
    def __init__(self, contamination: float = 0.05, n_estimators: int = 150,
                 random_state: int = 42):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
        )
        self.scaler       = StandardScaler()
        self.feature_cols = FEATURE_COLS
        self.is_fitted    = False
        self._train_stats: dict  = {}
        self._feature_means: dict = {}
        self._feature_stds: dict  = {}

    def _prepare(self, features_df: pd.DataFrame) -> tuple[np.ndarray, list[str]]:
        cols = [c for c in self.feature_cols if c in features_df.columns]
        return features_df[cols].fillna(0).values, cols

    def fit(self, features_df: pd.DataFrame) -> "AnomalyDetector":
        X, used_cols = self._prepare(features_df)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted   = True
        self._used_cols  = used_cols

        # Guardar estadísticas para explicabilidad (z-scores)
        for col in used_cols:
            vals = features_df[col].fillna(0)
            self._feature_means[col] = float(vals.mean())
            self._feature_stds[col]  = float(vals.std() + 1e-6)

        self._train_stats = {
            "n_requests_mean": self._feature_means.get("n_sys_requests", 0),
            "n_requests_std":  self._feature_stds.get("n_sys_requests", 1),
            "n_buckets":       len(features_df),
            "used_features":   len(used_cols),
        }
        return self

    def score(self, features_df: pd.DataFrame) -> pd.Series:
        """-1.0 = muy anómalo, 0.0 = neutral, positivo = muy normal."""
        X, _ = self._prepare(features_df)
        X_scaled = self.scaler.transform(X)
        return pd.Series(self.model.score_samples(X_scaled),
                         index=features_df.index, name="anomaly_score")

    def predict(self, features_df: pd.DataFrame) -> pd.Series:
        """-1 = anomalía, 1 = normal."""
        X, _ = self._prepare(features_df)
        X_scaled = self.scaler.transform(X)
        return pd.Series(self.model.predict(X_scaled),
                         index=features_df.index, name="prediction")

    def explain(self, bucket_row: pd.Series, top_n: int = 5) -> list[dict]:
        """
        Para un bucket anómalo, retorna las top_n features que más se
        desvían del baseline de entrenamiento (por z-score).
        """
        deviations = []
        for col, mean in self._feature_means.items():
            if col not in bucket_row.index:
                continue
            val = float(bucket_row[col])
            std = self._feature_stds.get(col, 1)
            z   = (val - mean) / std
            deviations.append({
                "feature":  col,
                "label":    FEATURE_LABELS.get(col, col),
                "value":    round(val, 4),
                "baseline": round(mean, 4),
                "z_score":  round(z, 2),
                "direction": "(alto)" if z > 0 else "(bajo)",
            })
        deviations.sort(key=lambda x: abs(x["z_score"]), reverse=True)
        return deviations[:top_n]

    def classify_type(self, features_df: pd.DataFrame,
                      scores: pd.Series, preds: pd.Series) -> pd.DataFrame:
        mean_req = self._train_stats.get("n_requests_mean", 0)
        std_req  = self._train_stats.get("n_requests_std",  1)
        spike_threshold = mean_req + SPIKE_SIGMA * std_req

        anomaly_idx = sorted(features_df.index[preds == -1].tolist())

        # Detectar runs de buckets consecutivos
        multi_bucket_set: set = set()
        if len(anomaly_idx) >= 2:
            run = [anomaly_idx[0]]
            for i in range(1, len(anomaly_idx)):
                gap = (anomaly_idx[i] - anomaly_idx[i - 1]).total_seconds() / 60
                if gap <= MULTI_BUCKET_GAP:
                    run.append(anomaly_idx[i])
                else:
                    if len(run) >= MULTI_BUCKET_N:
                        multi_bucket_set.update(run)
                    run = [anomaly_idx[i]]
            if len(run) >= MULTI_BUCKET_N:
                multi_bucket_set.update(run)

        results = []
        for idx in anomaly_idx:
            row   = features_df.loc[idx]
            score = float(scores.loc[idx])
            n_req = float(row.get("n_sys_requests", 0))

            if idx in multi_bucket_set:
                a_type = "MULTI_BUCKET"
            elif n_req > spike_threshold:
                a_type = "SPIKE"
            else:
                a_type = "CATEGORIZATION"

            severity = "HIGH" if score < -0.3 else ("MEDIUM" if score < -0.15 else "LOW")

            # Explicación de las top 5 features más desviadas
            top_devs = self.explain(row, top_n=5)

            results.append({
                "bucket":          idx,
                "anomaly_type":    a_type,
                "severity":        severity,
                "anomaly_score":   score,
                "top_deviations":  top_devs,
                "reason":          _build_reason(a_type, row, top_devs, spike_threshold),
                "attack_category": classify_attack_type(top_devs),
            })

        return pd.DataFrame(results)


def _build_reason(a_type: str, row: pd.Series,
                  top_devs: list[dict], spike_threshold: float) -> str:
    """Genera una frase legible explicando por qué se detectó la anomalía."""
    if not top_devs:
        return "Patrón estadístico inusual sin feature dominante."

    top = top_devs[0]
    if a_type == "SPIKE":
        n = int(row.get("n_sys_requests", 0))
        return (f"Pico de tráfico: {n:,} requests en 5 min "
                f"(umbral: {spike_threshold:,.0f}). "
                f"Feature más desviada: {top['label']} = {top['value']} "
                f"(z={top['z_score']}).")
    if a_type == "MULTI_BUCKET":
        return (f"Patrón sostenido en múltiples ventanas. "
                f"Feature dominante: {top['label']} = {top['value']} "
                f"(z={top['z_score']}, baseline={top['baseline']}).")
    # CATEGORIZATION
    return (f"Combinación inusual de patrones. "
            f"Top feature: {top['label']} = {top['value']} "
            f"({top['direction']}, z={top['z_score']}, "
            f"baseline={top['baseline']}).")
