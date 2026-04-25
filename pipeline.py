import time
import os

import pandas as pd
from ingestion import fetch_all_logs, get_window_info
from preprocessing import build_dataframe, split_by_type, flag_security_events
from hana_client import get_connection, create_tables_if_not_exist, load_system_logs, load_llm_logs

# Backoff en segundos entre reintentos cuando la API aún no se actualizó.
# Progresión: 5 → 10 → 30 → 60 → 60 → 60 ...
POLL_BACKOFF = [5, 10, 30, 60]


def _wait_for_new_window(last_window_start: str) -> dict:
    """
    Consulta /info con backoff hasta detectar que window_start cambió.
    Retorna el nuevo info dict cuando hay ventana nueva.
    """
    delays = iter(POLL_BACKOFF)
    next_delay = POLL_BACKOFF[-1]   # valor tope para reintentos posteriores

    while True:
        try:
            info = get_window_info()
            if info["window_start"] != last_window_start:
                print(f"[PIPELINE] Nueva ventana detectada: "
                      f"{last_window_start} → {info['window_start']}")
                return info
            else:
                try:
                    next_delay = next(delays)
                except StopIteration:
                    pass   # mantiene el último valor (60 s)
                print(f"[PIPELINE] API sin cambios (ventana: {info['window_start']}) "
                      f"— reintento en {next_delay} s")
                time.sleep(next_delay)
        except Exception as e:
            print(f"[PIPELINE] Error consultando /info: {e} — reintento en 30 s")
            time.sleep(30)


def run_pipeline():
    print("\n" + "="*60)
    print("[PIPELINE] Iniciando ciclo de ingesta...")

    try:
        # 1. EXTRACT — Descargar todos los logs de la ventana actual
        records, window_info = fetch_all_logs()

        # 2. TRANSFORM — Limpiar y separar
        df = build_dataframe(records)
        df_system, df_llm = split_by_type(df)
        df_system = flag_security_events(df_system)

        # 3. EXPORT — Guardar a CSVs incrementales
        # Filtrar columnas específicas
        df_llm = df_llm.drop(columns=['sourceip', 'http_status_code'], errors='ignore')
        llm_columns = [col for col in df_system.columns if 'llm' in col.lower()]
        df_system = df_system.drop(columns=llm_columns, errors='ignore')

        # Nombres de archivos
        output_dir = "exports"
        os.makedirs(output_dir, exist_ok=True)
        csv_file = f"{output_dir}/LOGS_EXPORT.csv"
        csv_llm_file = f"{output_dir}/LOGS_LLM.csv"
        csv_system_file = f"{output_dir}/LOGS_SYSTEM.csv"

        # Función para append incremental
        def append_to_csv(file_path, new_df):
            if os.path.exists(file_path):
                existing_df = pd.read_csv(file_path, encoding='utf-8')
                combined = pd.concat([existing_df, new_df], ignore_index=True)
                combined = combined.drop_duplicates(subset=['_id'], keep='last')
            else:
                combined = new_df
            combined.to_csv(file_path, index=False, encoding='utf-8')

        # Append a los CSVs
        append_to_csv(csv_file, df)
        append_to_csv(csv_llm_file, df_llm)
        append_to_csv(csv_system_file, df_system)

        print(f"[PIPELINE] CSVs actualizados: {len(df)} registros ({len(df_llm)} LLM, {len(df_system)} sistema)")

        # 4. LOAD — Enviar a HANA Cloud (UPSERT evita duplicados por _id)
        conn = get_connection()
        try:
            create_tables_if_not_exist(conn)
            load_system_logs(conn, df_system)
            load_llm_logs(conn, df_llm)
        finally:
            conn.close()

        print(f"[PIPELINE] Ciclo completado para ventana: {window_info['window_start']}")

    except Exception as e:
        print(f"[PIPELINE] ERROR en el ciclo: {e}")


if __name__ == "__main__":
    # Obtener ventana inicial para tener referencia de comparación
    try:
        current_info = get_window_info()
        last_window  = current_info["window_start"]
        print(f"[PIPELINE] Ventana inicial: {last_window} — descargando datos...")
        run_pipeline()
    except Exception as e:
        print(f"[PIPELINE] Error en arranque: {e}")
        last_window = None

    # Ciclos siguientes: esperar cambio real en la API antes de ingestar
    while True:
        new_info    = _wait_for_new_window(last_window)
        last_window = new_info["window_start"]
        run_pipeline()