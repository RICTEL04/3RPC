import os
import json
from datetime import datetime

import joblib

MODEL_DIR     = "models"
KEEP_VERSIONS = 3   # cuántas versiones recientes conservar; las más antiguas se eliminan


def _cleanup_old_models() -> None:
    """Borra versiones obsoletas dejando solo las KEEP_VERSIONS más recientes."""
    versions = list_versions()          # ordenadas cronológicamente (asc)
    to_delete = versions[:-KEEP_VERSIONS] if len(versions) > KEEP_VERSIONS else []
    for meta in to_delete:
        for path in (meta.get("model_path", ""),
                     meta.get("model_path", "").replace(".pkl", ".json")):
            if path and os.path.exists(path):
                os.remove(path)
                print(f"[ML] Modelo obsoleto eliminado: {os.path.basename(path)}")


def save_model(detector, metadata: dict = None) -> str:
    os.makedirs(MODEL_DIR, exist_ok=True)
    version = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    model_path = os.path.join(MODEL_DIR, f"detector_{version}.pkl")
    meta_path  = os.path.join(MODEL_DIR, f"detector_{version}.json")
    latest     = os.path.join(MODEL_DIR, "latest.json")

    joblib.dump(detector, model_path)

    meta = {
        "version":    version,
        "saved_at":   datetime.utcnow().isoformat(),
        "model_path": model_path,
        "train_stats": detector._train_stats,
        **(metadata or {}),
    }
    for path in (meta_path, latest):
        with open(path, "w") as f:
            json.dump(meta, f, indent=2)

    print(f"[ML] Modelo v{version} guardado → {model_path}")
    _cleanup_old_models()
    return version


def load_latest_model():
    latest = os.path.join(MODEL_DIR, "latest.json")
    if not os.path.exists(latest):
        return None, None
    with open(latest) as f:
        meta = json.load(f)
    detector = joblib.load(meta["model_path"])
    print(f"[ML] Modelo v{meta['version']} cargado")
    return detector, meta


def list_versions() -> list[dict]:
    if not os.path.exists(MODEL_DIR):
        return []
    versions = []
    for fname in sorted(os.listdir(MODEL_DIR)):
        if fname.endswith(".json") and fname != "latest.json":
            with open(os.path.join(MODEL_DIR, fname)) as f:
                versions.append(json.load(f))
    return versions
