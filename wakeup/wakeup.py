"""
HANA Wakeup — corre en Cloud Foundry 24/7.

Verifica el estado de HANA Cloud cada CHECK_INTERVAL segundos via
Service Manager API. Si detecta que está detenida o fallida, envía
el comando de inicio automáticamente.

No requiere conexión directa a HANA — solo usa la SM API REST.
"""

import base64
import json
import logging
import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [WAKEUP] - %(levelname)s - %(message)s",
)
logger = logging.getLogger("WAKEUP")

# ── Config ────────────────────────────────────────────────────────────────────
CHECK_INTERVAL   = 300   # segundos entre verificaciones (5 min)
START_RETRY_WAIT = 60    # segundos entre checks tras enviar start

UAA_URL          = os.getenv("UAA_URL",          "")
SM_URL           = os.getenv("SM_URL",           "")
SM_CLIENT_ID     = os.getenv("SM_CLIENT_ID",     "")
SM_CLIENT_SECRET = os.getenv("SM_CLIENT_SECRET", "")
HANA_INSTANCE_ID = os.getenv("HANA_INSTANCE_ID", "")


# ── Service Manager API ───────────────────────────────────────────────────────

def _get_token() -> str | None:
    try:
        credentials = base64.b64encode(
            f"{SM_CLIENT_ID}:{SM_CLIENT_SECRET}".encode()
        ).decode()
        resp = requests.get(
            f"{UAA_URL}/oauth/token?grant_type=client_credentials",
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type":  "application/x-www-form-urlencoded",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]
    except Exception as e:
        logger.warning(f"Token fallido: {e}")
        return None


def _get_state(token: str) -> tuple[str, bool | None]:
    """Retorna (op_state, service_stopped)."""
    try:
        headers = {"Authorization": f"Bearer {token}"}

        r1 = requests.get(
            f"{SM_URL}/v1/service_instances/{HANA_INSTANCE_ID}",
            headers=headers, timeout=30,
        )
        r1.raise_for_status()
        op_state = r1.json().get("last_operation", {}).get("state", "unknown")

        r2 = requests.get(
            f"{SM_URL}/v1/service_instances/{HANA_INSTANCE_ID}/parameters",
            headers=headers, timeout=30,
        )
        r2.raise_for_status()
        service_stopped = r2.json().get("data", {}).get("serviceStopped", None)

        return op_state, service_stopped
    except Exception as e:
        logger.warning(f"State check fallido: {e}")
        return "unknown", None


def _describe(op_state: str, service_stopped) -> str:
    if   op_state == "succeeded"   and service_stopped is False: return "Running"
    elif op_state == "succeeded"   and service_stopped is True:  return "Stopped"
    elif op_state == "in progress" and service_stopped is False: return "Starting"
    elif op_state == "in progress" and service_stopped is True:  return "Stopping"
    elif op_state == "failed":                                    return "Failed"
    else: return f"Unknown (op={op_state}, stopped={service_stopped})"


def _send_start(token: str) -> int | None:
    try:
        resp = requests.patch(
            f"{SM_URL}/v1/service_instances/{HANA_INSTANCE_ID}",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type":  "application/json",
            },
            data=json.dumps({"parameters": {"data": {"serviceStopped": False}}}),
            timeout=30,
        )
        return resp.status_code
    except Exception as e:
        logger.warning(f"Start request fallido: {e}")
        return None


# ── Loop principal ────────────────────────────────────────────────────────────

def run():
    if not all([UAA_URL, SM_URL, SM_CLIENT_ID, SM_CLIENT_SECRET, HANA_INSTANCE_ID]):
        logger.error("Variables de entorno incompletas — revisa el manifest.yml")
        return

    logger.info("=" * 55)
    logger.info("  HANA WAKEUP — monitoreo activo")
    logger.info(f"  Verificación cada {CHECK_INTERVAL}s")
    logger.info(f"  Instancia: {HANA_INSTANCE_ID}")
    logger.info("=" * 55)

    while True:
        token = _get_token()
        if token is None:
            logger.error("No se pudo obtener token — reintentando en 60s")
            time.sleep(60)
            continue

        op_state, service_stopped = _get_state(token)
        estado = _describe(op_state, service_stopped)
        logger.info(f"Estado HANA: {estado}")

        # Si está corriendo, todo OK
        if op_state == "succeeded" and service_stopped is False:
            time.sleep(CHECK_INTERVAL)
            continue

        # Si está arrancando, esperar
        if op_state == "in progress" and service_stopped is False:
            logger.info("HANA está arrancando — esperando 60s...")
            time.sleep(START_RETRY_WAIT)
            continue

        # Detenida, fallida o desconocida → enviar start
        logger.warning(f"HANA no está activa ({estado}) — enviando start...")
        code = _send_start(token)

        if   code in (200, 202): logger.info(f"Start aceptado (HTTP {code})")
        elif code == 422:        logger.info("HANA ya está procesando una operación")
        elif code == 502:        logger.info("HANA aún no lista para recibir comandos")
        elif code is None:       logger.warning("Start request falló completamente")
        else:                    logger.warning(f"Respuesta inesperada: HTTP {code}")

        time.sleep(START_RETRY_WAIT)


if __name__ == "__main__":
    run()
