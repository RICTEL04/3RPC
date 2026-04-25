"""
Heartbeat sender — corre dentro de main_pipeline.py en un hilo separado.

Escribe un pulso a HANA cada HEARTBEAT_INTERVAL segundos con:
  - Timestamp exacto del envío
  - Estado del pipeline (RUNNING, ERROR)
  - Número de ciclo completado
  - Última ventana procesada

El watchdog externo lee esta tabla para detectar si el pipeline cayó.
"""

import logging
import socket
import threading
import time
from datetime import datetime

from hdbcli import dbapi
from config import HANA_HOST, HANA_PORT, HANA_USER, HANA_PASS, HANA_SCHEMA

logger = logging.getLogger("HEARTBEAT")

HEARTBEAT_INTERVAL = 60     # segundos entre pulsos
PIPELINE_ID        = "main_pipeline"   # identificador fijo — 1 fila en la tabla


# ── Crear tabla si no existe ──────────────────────────────────────────────────

def _ensure_table(conn):
    cursor = conn.cursor()
    try:
        cursor.execute(f"""
            CREATE TABLE "{HANA_SCHEMA}"."PIPELINE_HEARTBEAT" (
                "pipeline_id"       NVARCHAR(50)  PRIMARY KEY,
                "sent_at"           TIMESTAMP,
                "pipeline_host"     NVARCHAR(100),
                "cycle"             INTEGER,
                "status"            NVARCHAR(20),
                "last_window_start" NVARCHAR(50),
                "uptime_min"        DECIMAL(10,2)
            )
        """)
        conn.commit()
        logger.info("Tabla PIPELINE_HEARTBEAT creada")
    except Exception as e:
        if getattr(e, "errorcode", None) == 288 or "duplicate" in str(e).lower():
            pass
        else:
            raise
    finally:
        cursor.close()


# ── Enviar un pulso ───────────────────────────────────────────────────────────

def _send_pulse(cycle: int, last_window: str, status: str, start_time: float):
    try:
        conn = dbapi.connect(
            address=HANA_HOST, port=HANA_PORT,
            user=HANA_USER, password=HANA_PASS,
            encrypt=True, sslValidateCertificate=False,
        )
        _ensure_table(conn)
        uptime_min = (time.time() - start_time) / 60
        now_str    = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        host       = socket.gethostname()

        cursor = conn.cursor()
        cursor.execute(f"""
            UPSERT "{HANA_SCHEMA}"."PIPELINE_HEARTBEAT" (
                "pipeline_id","sent_at","pipeline_host",
                "cycle","status","last_window_start","uptime_min"
            ) VALUES (?,?,?,?,?,?,?) WITH PRIMARY KEY
        """, (PIPELINE_ID, now_str, host, cycle, status, last_window or "", round(uptime_min, 2)))
        conn.commit()
        cursor.close()
        conn.close()
        logger.debug(f"Pulso enviado — ciclo={cycle} status={status} uptime={uptime_min:.1f}min")
    except Exception as e:
        logger.warning(f"Fallo al enviar pulso: {e}")


# ── Hilo de heartbeat ─────────────────────────────────────────────────────────

class HeartbeatThread(threading.Thread):
    """
    Hilo daemon que manda un pulso a HANA cada HEARTBEAT_INTERVAL segundos.
    Se actualiza desde el pipeline principal via set_state().
    Muere automáticamente cuando el proceso principal termina (daemon=True).
    """

    def __init__(self):
        super().__init__(daemon=True, name="HeartbeatThread")
        self._cycle       = 0
        self._last_window = None
        self._status      = "STARTING"
        self._start_time  = time.time()
        self._lock        = threading.Lock()

    def set_state(self, cycle: int, last_window: str, status: str = "RUNNING"):
        with self._lock:
            self._cycle       = cycle
            self._last_window = last_window
            self._status      = status

    def set_error(self):
        with self._lock:
            self._status = "ERROR"

    def run(self):
        logger.info("Heartbeat activo — pulso cada 60 s")
        while True:
            with self._lock:
                c, w, s = self._cycle, self._last_window, self._status
            _send_pulse(c, w, s, self._start_time)
            time.sleep(HEARTBEAT_INTERVAL)
