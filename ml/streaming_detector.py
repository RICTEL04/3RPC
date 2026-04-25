"""
Detector de anomalías incremental usando Half-Space Trees (HST).

HST actualiza su modelo con cada nuevo bucket sin re-entrenar desde cero.
Es resistente a concept drift lento porque usa una ventana deslizante interna.

Se usa en paralelo con Isolation Forest:
  - HST  → detecta cambios bruscos rápido (cada 5 min)
  - IForest → valida contra baseline histórico (cada hora)
Una anomalía confirmada por AMBOS tiene mucha más confianza.
"""
from river.anomaly import HalfSpaceTrees
import pandas as pd

# Columnas que el modelo streaming usa (las más reactivas a cambios rápidos)
STREAMING_FEATURES = [
    "n_sys_requests", "error_rate", "security_event_rate",
    "rate_limit_rate", "server_error_rate", "top_ip_share",
    "n_llm_requests", "llm_error_rate", "llm_timeout_rate",
    "total_llm_cost", "pct_content_filter", "total_requests",
]

# Score >= este umbral → anomalía según HST (escala 0-1, 1 = más anómalo)
HST_THRESHOLD = 0.7


class StreamingDetector:
    """
    Wrapper de Half-Space Trees para detección incremental.
    Aprende con cada bucket nuevo y retiene memoria de ventana corta.
    """

    def __init__(self, n_trees: int = 25, height: int = 8,
                 window_size: int = 50):
        # window_size: cuántos buckets recientes considera "presente"
        self.model = HalfSpaceTrees(
            n_trees=n_trees,
            height=height,
            window_size=window_size,
        )
        self.threshold  = HST_THRESHOLD
        self.n_learned  = 0

    def _to_dict(self, row: pd.Series) -> dict:
        return {
            col: float(row[col])
            for col in STREAMING_FEATURES
            if col in row.index and pd.notna(row[col])
        }

    def learn_and_score(self, features_df: pd.DataFrame) -> pd.Series:
        """
        Para cada bucket: primero puntúa (score), luego aprende (learn_one).
        Así el score refleja cuánto se desvía del pasado reciente.
        El orden importa: score antes de learn evita que el modelo "normalice"
        lo que acaba de ver antes de evaluarlo.
        """
        scores = {}
        for bucket, row in features_df.iterrows():
            x = self._to_dict(row)
            if not x:
                scores[bucket] = 0.0
                continue
            # Primero puntúa con lo aprendido hasta ahora
            score = self.model.score_one(x)
            scores[bucket] = score
            # Luego aprende de este bucket
            self.model.learn_one(x)
            self.n_learned += 1

        return pd.Series(scores, name="hst_score")

    def flag_anomalies(self, hst_scores: pd.Series) -> pd.Series:
        """Retorna True en buckets que superan el umbral HST."""
        return hst_scores >= self.threshold

    @property
    def is_warmed_up(self) -> bool:
        """HST necesita ver al menos window_size buckets antes de ser confiable."""
        return self.n_learned >= self.model.window_size
