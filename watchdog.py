"""
Watchdog 3RPC — corre en servidor físico 24/7.

Monitorea la tabla PIPELINE_HEARTBEAT en HANA cada CHECK_INTERVAL segundos.

Lógica de decisión:
  1. No puede conectar a HANA
       → llama a restart_hana() con la lógica Service Manager que ya funciona
       → espera y reintenta hasta que HANA responda

  2. Conecta a HANA pero el último pulso tiene más de HEARTBEAT_TIMEOUT segundos
       → Cloud Foundry / pipeline caído → cf restart

  3. Pulso reciente y status="RUNNING"
       → Todo OK — continuar monitoreando

Uso:
  python watchdog.py
"""

import base64
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from hdbcli import dbapi

load_dotenv()

from config import HANA_HOST, HANA_PORT, HANA_USER, HANA_PASS, HANA_SCHEMA

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [WATCHDOG] - %(levelname)s - %(message)s",
)
logger = logging.getLogger("WATCHDOG")

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════

CHECK_INTERVAL    = 60    # segundos entre verificaciones
HEARTBEAT_TIMEOUT = 180   # segundos sin pulso → pipeline caído
CF_RECOVERY_WAIT  = 120   # espera tras reiniciar CF
MAX_RESTART_RETRIES = 3

# CF CLI — para reiniciar el pipeline
CF_API      = os.getenv("CF_API",      "")
CF_USER     = os.getenv("CF_USER",     "")
CF_PASS     = os.getenv("CF_PASS",     "")
CF_ORG      = os.getenv("CF_ORG",      "")
CF_SPACE    = os.getenv("CF_SPACE",    "")
CF_APP_NAME = os.getenv("CF_APP_NAME", "3RPC")

# Service Manager — para start/stop de HANA Cloud
UAA_URL       = os.getenv("UAA_URL",        "https://c36a9ecetrial.authentication.us10.hana.ondemand.com")
SM_URL        = os.getenv("SM_URL",         "https://service-manager.cfapps.us10.hana.ondemand.com")
SM_CLIENT_ID  = os.getenv("SM_CLIENT_ID",   "")
SM_CLIENT_SECRET = os.getenv("SM_CLIENT_SECRET", "")
HANA_INSTANCE_ID = os.getenv("HANA_INSTANCE_ID", "")


# ══════════════════════════════════════════════════════════════════════════════
# HANA CLOUD — START/STOP via Service Manager (lógica probada)
# ══════════════════════════════════════════════════════════════════════════════

def _get_sm_token(retries: int = 3) -> str | None:
    for attempt in range(retries):
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
            logger.warning(f"Token SM fallido (intento {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(30)
    return None


def _get_hana_state(token: str, retries: int = 3) -> tuple[str, bool | None]:
    """Retorna (op_state, service_stopped)."""
    for attempt in range(retries):
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
            logger.warning(f"State check fallido (intento {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(30)
    return "unknown", None


def _describe_hana_state(op_state: str, service_stopped) -> str:
    if   op_state == "succeeded"   and service_stopped is False: return "Running"
    elif op_state == "succeeded"   and service_stopped is True:  return "Stopped"
    elif op_state == "in progress" and service_stopped is False: return "Starting/Refreshing"
    elif op_state == "in progress" and service_stopped is True:  return "Stopping"
    elif op_state == "failed":                                    return "Failed"
    else: return f"Unknown (op={op_state}, stopped={service_stopped})"


def _send_hana_start(token: str, retries: int = 3) -> int | None:
    for attempt in range(retries):
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
            logger.warning(f"Start request fallido (intento {attempt+1}/{retries}): {e}")
            if attempt < retries - 1:
                time.sleep(30)
    return None


def restart_hana() -> bool:
    """
    Enciende HANA Cloud via Service Manager.
    Reintenta el start cada 5 minutos hasta confirmar que está Running.
    """
    if not all([SM_CLIENT_ID, SM_CLIENT_SECRET, HANA_INSTANCE_ID]):
        logger.error("SM_CLIENT_ID / SM_CLIENT_SECRET / HANA_INSTANCE_ID no configurados en .env")
        return False

    cycle = 1
    while True:
        token = _get_sm_token()
        if token is None:
            logger.error("No se pudo obtener token SM — reintentando en 60s")
            time.sleep(60)
            continue

        logger.info(f"Enviando start request a HANA (intento #{cycle})...")
        code = _send_hana_start(token)

        if   code in (200, 202): logger.info("Start request aceptado")
        elif code == 422:        logger.info("HANA ya está procesando una operación")
        elif code == 502:        logger.info("HANA aún no está lista para recibir comandos")
        elif code is None:       logger.warning("Request falló completamente")
        else:                    logger.warning(f"Respuesta inesperada: {code}")

        # Verificar cada minuto durante 5 minutos
        logger.info("Verificando estado cada minuto durante 5 minutos...")
        for minute in range(1, 6):
            time.sleep(60)
            token = _get_sm_token()
            if token is None:
                logger.warning(f"  [{minute}/5 min] No se pudo refrescar token")
                continue
            op_state, service_stopped = _get_hana_state(token)
            estado = _describe_hana_state(op_state, service_stopped)
            logger.info(f"  [{minute}/5 min] HANA estado: {estado}")
            if op_state == "succeeded" and service_stopped is False:
                logger.info("HANA Cloud está corriendo")
                return True

        logger.warning("HANA aún no responde después de 5 min — enviando otro start...")
        cycle += 1


# ══════════════════════════════════════════════════════════════════════════════
# CLOUD FOUNDRY — reiniciar pipeline
# ══════════════════════════════════════════════════════════════════════════════

def _cf_login() -> bool:
    try:
        result = subprocess.run(
            ["cf", "login", "-a", CF_API, "-u", CF_USER,
             "-p", CF_PASS, "-o", CF_ORG, "-s", CF_SPACE],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            logger.info("CF login OK")
            return True
        logger.error(f"CF login falló: {result.stderr.strip()}")
        return False
    except FileNotFoundError:
        logger.error("CF CLI no encontrado — instálalo desde https://docs.cloudfoundry.org/cf-cli/install-go-cli.html")
        return False
    except Exception as e:
        logger.error(f"CF login error: {e}")
        return False


def _get_cf_app_state() -> str:
    """Retorna el estado actual de la app CF: STARTED, STOPPED, CRASHED, unknown."""
    try:
        result = subprocess.run(
            ["cf", "app", CF_APP_NAME],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout.lower()
        if "started" in output:
            return "STARTED"
        if "stopped" in output:
            return "STOPPED"
        if "crashed" in output:
            return "CRASHED"
        return "unknown"
    except Exception:
        return "unknown"


def restart_cf_pipeline() -> bool:
    """
    Reinicia la app de Cloud Foundry y verifica que quede STARTED.
    Reintenta cada 5 minutos si no levanta, igual que el restart de HANA.
    """
    if not all([CF_API, CF_USER, CF_PASS, CF_ORG, CF_SPACE]):
        logger.error("Credenciales CF incompletas en .env — no se puede reiniciar el pipeline")
        return False

    cycle = 1
    while True:
        logger.warning(f"Reiniciando pipeline '{CF_APP_NAME}' en CF (intento #{cycle})...")

        if not _cf_login():
            logger.error("CF login falló — reintentando en 60s")
            time.sleep(60)
            cycle += 1
            continue

        try:
            result = subprocess.run(
                ["cf", "restart", CF_APP_NAME],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                logger.info("CF restart enviado correctamente")
            else:
                logger.warning(f"CF restart respondió con error: {result.stderr.strip()}")
        except Exception as e:
            logger.error(f"Error ejecutando cf restart: {e}")

        # Verificar estado cada minuto durante 5 minutos
        logger.info("Verificando estado de la app cada minuto durante 5 minutos...")
        for minute in range(1, 6):
            time.sleep(60)
            state = _get_cf_app_state()
            logger.info(f"  [{minute}/5 min] App '{CF_APP_NAME}': {state}")

            if state == "STARTED":
                logger.info(f"Pipeline '{CF_APP_NAME}' está corriendo en CF")
                return True
            if state == "CRASHED":
                logger.error("App en estado CRASHED — forzando restart inmediato")
                break

        logger.warning("App aún no está STARTED después de 5 min — reintentando...")
        cycle += 1


# ══════════════════════════════════════════════════════════════════════════════
# MONITOREO DE HEARTBEAT
# ══════════════════════════════════════════════════════════════════════════════

def _check_hana_and_heartbeat() -> tuple[bool, dict | None]:
    try:
        conn = dbapi.connect(
            address=HANA_HOST, port=HANA_PORT,
            user=HANA_USER, password=HANA_PASS,
            encrypt=True, sslValidateCertificate=False,
        )
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT "pipeline_id","sent_at","cycle","status",
                   "last_window_start","uptime_min","pipeline_host"
            FROM "{HANA_SCHEMA}"."PIPELINE_HEARTBEAT"
            WHERE "pipeline_id" = 'main_pipeline'
        """)
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        if row is None:
            return True, None

        return True, {
            "pipeline_id":       row[0],
            "sent_at":           row[1],
            "cycle":             row[2],
            "status":            row[3],
            "last_window_start": row[4],
            "uptime_min":        row[5],
            "pipeline_host":     row[6],
        }
    except Exception as e:
        logger.error(f"No se pudo conectar a HANA: {e}")
        return False, None


def _seconds_since(sent_at) -> float:
    if sent_at is None:
        return float("inf")
    if hasattr(sent_at, "tzinfo") and sent_at.tzinfo is None:
        sent_at = sent_at.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - sent_at).total_seconds()


# ══════════════════════════════════════════════════════════════════════════════
# LOOP PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def run_watchdog():
    logger.info("=" * 62)
    logger.info("  3RPC WATCHDOG  —  monitoreo continuo activo")
    logger.info(f"  Check cada {CHECK_INTERVAL}s | Timeout heartbeat: {HEARTBEAT_TIMEOUT}s")
    logger.info("=" * 62)

    cf_restarts   = 0
    hana_restarts = 0

    while True:
        hana_ok, hb = _check_hana_and_heartbeat()

        # ── HANA caída ────────────────────────────────────────────────────────
        if not hana_ok:
            hana_restarts += 1
            logger.critical(f"HANA NO RESPONDE — iniciando recovery #{hana_restarts}")
            if hana_restarts > MAX_RESTART_RETRIES:
                logger.critical(
                    f"HANA lleva {hana_restarts} intentos sin éxito — "
                    f"verifica manualmente en BTP Cockpit"
                )
            restart_hana()
            # restart_hana() ya espera internamente hasta confirmar que HANA está up
            continue

        hana_restarts = 0

        # ── HANA OK pero pipeline nunca arrancó ───────────────────────────────
        if hb is None:
            logger.warning("HANA OK — sin heartbeat registrado aún (pipeline no ha arrancado)")
            time.sleep(CHECK_INTERVAL)
            continue

        # ── Verificar frescura del pulso ──────────────────────────────────────
        lag = _seconds_since(hb["sent_at"])
        logger.info(
            f"Heartbeat OK — ciclo={hb['cycle']} | {hb['status']} | "
            f"host={hb['pipeline_host']} | uptime={hb['uptime_min']:.1f}min | "
            f"pulso hace {lag:.0f}s | ventana={hb['last_window_start']}"
        )

        if lag > HEARTBEAT_TIMEOUT:
            cf_restarts += 1
            logger.critical(
                f"PIPELINE CAIDO — sin pulso hace {lag:.0f}s — "
                f"reiniciando CF (intento #{cf_restarts})"
            )
            if cf_restarts > MAX_RESTART_RETRIES:
                logger.critical(
                    f"Pipeline lleva {cf_restarts} reinicios — intervención manual requerida"
                )
            restart_cf_pipeline()
            time.sleep(CF_RECOVERY_WAIT)
            continue

        cf_restarts = 0
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    run_watchdog()
