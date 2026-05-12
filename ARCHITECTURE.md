# 3RPC — Reporte Técnico de Arquitectura

**Versión:** 2.0  
**Fecha:** 2026-05-10  
**Autor:** Equipo 3RPC

---

## Índice

1. [Descripción general](#1-descripción-general)
2. [Estructura de directorios](#2-estructura-de-directorios)
3. [Componentes del sistema](#3-componentes-del-sistema)
4. [Flujo de datos](#4-flujo-de-datos)
5. [Módulo de ML](#5-módulo-de-ml)
6. [Esquema de base de datos (HANA)](#6-esquema-de-base-de-datos-hana)
7. [Monitoreo y recuperación](#7-monitoreo-y-recuperación)
8. [Despliegue en Cloud Foundry](#8-despliegue-en-cloud-foundry)
9. [Configuración y variables de entorno](#9-configuración-y-variables-de-entorno)
10. [Dependencias](#10-dependencias)

---

## 1. Descripción general

**3RPC** es un pipeline de ingesta, procesamiento y detección de anomalías para logs de una plataforma SAP. El sistema recolecta logs desde una API REST cada 30 minutos, los almacena en SAP HANA Cloud y aplica dos modelos de Machine Learning en paralelo para detectar comportamientos anómalos en tiempo cuasi-real.

<img width="1920" height="1080" alt="Arquitectura 3rpc" src="https://github.com/user-attachments/assets/95c37a93-3f79-4157-a5f2-47c03a86b744" />

### Capacidades principales

| Capacidad | Descripción |
|---|---|
| Ingesta automática | Descarga paginada de logs via API REST con detección de ventana temporal |
| Buffer ante fallos | Cola local JSON ante caídas de HANA; recovery idempotente via UPSERT |
| Detección de anomalías | Isolation Forest (batch, 24h baseline) + Half-Space Trees (streaming, incremental) |
| Clasificación de amenazas | 10 categorías: DDoS, Brute Force, LLM Prompt Injection, 5xx Overload, etc. |
| Alertas | POST a `/alert` en la API con mensaje estructurado ≤300 caracteres |
| Watchdog externo | Monitoreo de heartbeat con reinicio automático via CF CLI y Service Manager |

---

## 2. Estructura de directorios

```
3RPC/
├── main.py                    # Pipeline principal: ETL + ML combinados (CF)
├── pipeline.py                # Pipeline ETL standalone (uso alternativo)
├── ml_pipeline.py             # Pipeline ML standalone (uso alternativo)
├── config.py                  # Configuración global (lee variables de .env)
├── export_csv.py              # Utilidad local: exportar HANA a CSV
├── verify_anomalies.py        # Utilidad local: inspección de anomalías
├── manifest.yml               # Descriptor de despliegue Cloud Foundry
├── .cfignore                  # Exclusiones del push a CF
├── .env                       # Credenciales locales (gitignored)
├── .env.example               # Plantilla de variables de entorno
├── requirements.txt           # Dependencias Python
│
├── src/
│   ├── ingestion/
│   │   ├── api_client.py      # Descarga paginada paralela de la API
│   │   └── hana_client.py     # Conexión y carga UPSERT a HANA
│   │
│   ├── processing/
│   │   └── preprocessing.py   # Normalización, split y detección de eventos de seguridad
│   │
│   ├── ml/
│   │   ├── features.py        # Feature engineering (43 variables, buckets de 5 min)
│   │   ├── detector.py        # Isolation Forest con clasificación de tipo
│   │   ├── streaming_detector.py  # Half-Space Trees incremental
│   │   ├── versioning.py      # Serialización versionada de modelos
│   │   └── alert_sender.py    # Envío de alertas a la API
│   │
│   ├── monitoring/
│       ├── heartbeat.py       # Hilo daemon: pulso a HANA cada 60 s
│       └── watchdog.py        # Proceso externo: monitoreo y recovery automático
│   
├── exports/                   # CSVs locales (buffer; gitignored)
└── models/                    # Modelos serializados + estado HST (gitignored)
```

---

## 3. Componentes del sistema

### 3.1 `main.py` — Pipeline principal (Cloud Foundry)

Proceso único que combina ETL y ML en un ciclo continuo. Es el entrypoint desplegado en CF.

**Flujo por ciclo:**
1. Espera al próximo slot de reloj (`:00` o `:30` exactos)
2. Detecta cambio de ventana en `/info` (polling con backoff `5→10→30→60s`)
3. Drena la cola de pendientes si hay batches fallidos de ciclos anteriores
4. Ejecuta ETL completo: descarga → transformación → CSV local → HANA
5. Ejecuta scoring ML con los datos frescos recién ingestados
6. Guarda el estado del HST y el número de ciclo en disco

**Garantías de datos:**
- UPSERT por `_id` evita duplicados en HANA
- CSV local actúa como buffer permanente; si HANA falla, el batch se encola en `exports/pending_queue.json`
- Al reiniciar, `startup_recovery` re-sube los CSVs a HANA de forma idempotente

### 3.2 `src/ingestion/api_client.py`

Descarga logs de la API REST con paralelismo por página usando `ThreadPoolExecutor`.

| Endpoint | Uso |
|---|---|
| `GET /info` | Metadatos de la ventana: `window_start`, `window_end`, `total_pages`, `total_records` |
| `GET /logs/current?page=N` | Registros paginados de la ventana activa |

### 3.3 `src/ingestion/hana_client.py`

Gestiona la conexión a SAP HANA Cloud y la carga de datos.

- Conexión TLS encriptada (`encrypt=True`, `sslValidateCertificate=False`)
- UPSERT via `UPSERT ... WITH PRIMARY KEY` para idempotencia
- Crea las tablas automáticamente si no existen (`CREATE TABLE IF NOT EXISTS`)

### 3.4 `src/processing/preprocessing.py`

Transforma el JSON crudo de la API en DataFrames normalizados.

- `build_dataframe()`: normaliza timestamps, tipos y campos anidados
- `split_by_type()`: separa en `SYSTEM_LOGS` vs `LLM_LOGS` según `logtype`
- `flag_security_events()`: marca filas con `is_security_event=1` según patrones en `event_description`

---

## 4. Flujo de datos

```
API REST (/info, /logs/current)
        │
        ▼ fetch_all_logs()          [src/ingestion/api_client.py]
  JSON paginado paralelo
        │
        ▼ build_dataframe()         [src/processing/preprocessing.py]
  DataFrame normalizado
        │
        ├──▶ split_by_type()
        │         │
        │    ┌────┴────┐
        │    ▼         ▼
        │ df_system  df_llm
        │    │         │
        │    ▼         │
        │ flag_security_events()
        │    │         │
        ▼    ▼         ▼
  exports/LOGS_SYSTEM.csv
  exports/LOGS_LLM.csv            [buffer local permanente]
        │
        ▼ UPSERT                   [src/ingestion/hana_client.py]
  HANA: SYSTEM_LOGS
  HANA: LLM_LOGS
        │
        ▼ build_features()         [src/ml/features.py]
  features DataFrame (buckets 5 min, 43 variables)
        │
        ├──▶ IsolationForest.fit/score   [src/ml/detector.py]
        ├──▶ HalfSpaceTrees.learn_and_score [src/ml/streaming_detector.py]
        │
        ▼ classify_type()
  anomalies DataFrame
        │
        ├──▶ UPSERT → HANA: ANOMALIES
        └──▶ POST /alert            [src/ml/alert_sender.py]
```

---

## 5. Módulo de ML

### 5.1 Feature Engineering (`src/ml/features.py`)

Los logs se agrupan en **buckets de 5 minutos**. Para cada bucket se calculan **43 variables** distribuidas en cuatro categorías:

| Categoría | Variables (ejemplos) |
|---|---|
| Volumen e IPs | `n_sys_requests`, `n_unique_ips`, `top_ip_share` |
| HTTP status | `error_rate`, `client_error_rate`, `server_error_rate`, `rate_limit_rate` |
| Seguridad y logs | `security_event_rate`, `n_security_events`, `pct_error_logtype`, `method_entropy` |
| LLM | `n_llm_requests`, `llm_error_rate`, `avg_llm_latency`, `total_llm_cost`, `pct_content_filter` |

### 5.2 Isolation Forest (`src/ml/detector.py`)

| Parámetro | Valor |
|---|---|
| Estimadores | 150 árboles |
| Contaminación | 5% |
| Ventana de entrenamiento | Últimas 24 horas |
| Re-entrenamiento | Cada 2 ciclos (~1 hora) |
| Normalización | `StandardScaler` por feature |

Después del scoring, `classify_type()` asigna una categoría de amenaza a cada anomalía usando umbrales por z-score sobre las features más desviadas.

**Categorías de amenaza detectadas:**

| Categoría | Señal principal |
|---|---|
| DDoS / Traffic Flooding | Alto `n_sys_requests` + alto `rate_limit_rate` |
| Brute Force | Alto `n_unique_ips` + alto `pct_post` |
| LLM Prompt Injection | Alto `pct_content_filter` |
| Server Overload (5xx) | Alto `server_error_rate` |
| Geographic Concentration | Alto `top_region_share` |
| Reconnaissance / Scanning | Alto `n_unique_services` + bajo volumen |
| Security Event Escalation | Alto `security_event_rate` |
| LLM Service Degradation | Alto `llm_error_rate` + alto `avg_llm_latency` |
| Anomalous LLM Cost | Alto `total_llm_cost` o `max_llm_cost` |
| Unusual Statistical Pattern | Desviación general sin patrón específico |

### 5.3 Half-Space Trees (`src/ml/streaming_detector.py`)

Detector incremental de la librería `river`. Aprende de cada bucket nuevo sin re-entrenar desde cero.

| Parámetro | Valor |
|---|---|
| Árboles | 25 |
| Altura | 8 |
| Window size | 8 buckets (~40 min) |
| Threshold | 0.7 |
| Features | 12 (subconjunto de las 43 totales) |
| Warmup | ≥4 horas de datos antes de emitir alertas |

### 5.4 Combinación de modelos

```
IForest flagea bucket  +  HST flagea bucket  →  ALTA CONFIANZA (ambos coinciden)
IForest flagea bucket  (HST no)              →  Anomalía histórica
HST flagea bucket      (IForest no)          →  Cambio brusco reciente
```

Las anomalías confirmadas por ambos modelos se marcan con `hst_confirmed=True` en la tabla `ANOMALIES`.

### 5.5 Persistencia de modelos

`src/ml/versioning.py` guarda cada versión del IForest con metadata en `models/`:

```
models/
├── model_v1.pkl        # IForest serializado (joblib)
├── model_v1_meta.json  # training_hours, n_features, bucket_size, timestamp
├── hst_state.pkl       # Estado completo del HST (pickle)
└── ml_state.json       # Último ciclo y último timestamp evaluado
```

Al reiniciar, el pipeline restaura el HST y el estado ML para evitar re-calentamiento y gaps en el scoring.

---

## 6. Esquema de base de datos (HANA)

### `SYSTEM_LOGS`

| Columna | Tipo | Descripción |
|---|---|---|
| `_id` | `NVARCHAR(64)` PK | Identificador único del log |
| `timestamp` | `TIMESTAMP` | Timestamp del evento |
| `logtype` | `NVARCHAR(30)` | INFO, WARNING, ERROR, AUDIT, SECURITY, PERF, DEBUG |
| `sourceip` | `NVARCHAR(50)` | IP de origen |
| `port_service` | `NVARCHAR(50)` | Servicio/puerto destino |
| `http_status_code` | `INTEGER` | Código HTTP de respuesta |
| `is_security_event` | `TINYINT` | Flag 0/1: evento de seguridad detectado |
| `event_description` | `NCLOB` | Descripción del evento |
| `macro_region` | `NVARCHAR(50)` | Región geográfica |
| `sap_app_env` | `NVARCHAR(30)` | Entorno SAP (production, dev, etc.) |
| `_score` | `DECIMAL(10,6)` | Score de riesgo original de la API |

### `LLM_LOGS`

| Columna | Tipo | Descripción |
|---|---|---|
| `_id` | `NVARCHAR(64)` PK | Identificador único |
| `timestamp` | `TIMESTAMP` | Timestamp de la llamada |
| `llm_model_id` | `NVARCHAR(100)` | Identificador del modelo LLM |
| `llm_cost_usd` | `DECIMAL(10,6)` | Costo en USD de la llamada |
| `llm_response_time_ms` | `INTEGER` | Latencia en milisegundos |
| `llm_total_tokens` | `INTEGER` | Total de tokens procesados |
| `llm_status` | `NVARCHAR(30)` | Estado: success, error, timeout |
| `llm_finish_reason` | `NVARCHAR(50)` | Razón de fin: stop, content_filter, etc. |
| `sap_llm_response_size` | `INTEGER` | Tamaño de la respuesta |

### `ANOMALIES`

| Columna | Tipo | Descripción |
|---|---|---|
| `anomaly_id` | `NVARCHAR(64)` PK | UUID generado al detectar |
| `detected_at` | `TIMESTAMP` | Momento de detección |
| `bucket_start` | `TIMESTAMP` | Inicio del bucket de 5 min anómalo |
| `anomaly_type` | `NVARCHAR(30)` | Categoría de amenaza |
| `severity` | `NVARCHAR(10)` | HIGH / MEDIUM |
| `anomaly_score` | `DECIMAL(10,6)` | Score IForest (más negativo = más anómalo) |
| `n_requests` | `INTEGER` | Requests en el bucket |
| `n_unique_ips` | `INTEGER` | IPs únicas en el bucket |
| `error_rate` | `DECIMAL(10,4)` | Tasa de errores HTTP |
| `top_ip` | `NVARCHAR(50)` | IP más activa del bucket |
| `reason` | `NVARCHAR(500)` | Explicación legible de la anomalía |
| `attack_category` | `NVARCHAR(100)` | Categoría en inglés |
| `details_json` | `NCLOB` | JSON con features snapshot + IDs de logs relacionados |

### `PIPELINE_HEARTBEAT`

| Columna | Tipo | Descripción |
|---|---|---|
| `pipeline_id` | `NVARCHAR(50)` PK | Siempre `"main_pipeline"` |
| `sent_at` | `TIMESTAMP` | Último pulso recibido |
| `pipeline_host` | `NVARCHAR(100)` | Hostname del contenedor CF |
| `cycle` | `INTEGER` | Número de ciclo completado |
| `status` | `NVARCHAR(20)` | STARTING / RUNNING / ERROR |
| `last_window_start` | `NVARCHAR(50)` | Última ventana procesada |
| `uptime_min` | `DECIMAL(10,2)` | Minutos activo desde el arranque |

---

## 7. Monitoreo y recuperación

### 7.1 Heartbeat (`src/monitoring/heartbeat.py`)

Hilo daemon que corre dentro del proceso `main.py` en CF. Cada 60 segundos hace UPSERT en `PIPELINE_HEARTBEAT`. Si el proceso muere, el pulso se detiene.

### 7.2 Watchdog (`src/monitoring/watchdog.py`)

Proceso independiente que corre en **servidor físico** (fuera de CF). Consulta la tabla `PIPELINE_HEARTBEAT` cada 60 segundos.

```
Ciclo watchdog:
  ┌─ HANA no responde ──────────────────────────────────────────┐
  │  → restart_hana() via Service Manager API                    │
  │  → Polling de estado cada 1 min durante 5 min               │
  │  → Reintenta hasta MAX_RESTART_RETRIES=3                     │
  └──────────────────────────────────────────────────────────────┘
  ┌─ HANA OK, pulso > 180 s ────────────────────────────────────┐
  │  → restart_cf_pipeline() via CF CLI                          │
  │  → cf login → cf restart 3RPC                               │
  │  → Polling de estado CF cada 1 min durante 5 min            │
  └──────────────────────────────────────────────────────────────┘
  ┌─ HANA OK, pulso reciente ───────────────────────────────────┐
  │  → Log de estado y esperar 60 s                              │
  └──────────────────────────────────────────────────────────────┘
```

### 7.3 Recovery ante fallos de HANA

```
HANA cae durante ETL
        │
        ▼
_enqueue_pending(df_system, df_llm)
        │  Serializa batch en exports/pending_queue.json
        │
HANA vuelve (ciclo siguiente)
        │
        ▼
_drain_pending_queue(conn)
        │  Re-sube todos los batches pendientes via UPSERT
        │  Elimina pending_queue.json si todo se subió
        ▼
Ciclo normal continúa
```

---

## 8. Despliegue en Cloud Foundry

### `manifest.yml`

```yaml
applications:
  - name: 3RPC
    memory: 1G
    disk_quota: 1G
    instances: 1
    buildpacks:
      - python_buildpack
    command: python main.py
    no-route: true
    health-check-type: process
```

- `no-route: true`: proceso background sin endpoint HTTP
- `health-check-type: process`: CF verifica que el proceso siga corriendo

### Qué sube a CF

| Incluido | Excluido (`.cfignore`) |
|---|---|
| `main.py`, `pipeline.py`, `ml_pipeline.py` | `src/dashboard/` |
| `config.py`, `requirements.txt` | `src/monitoring/watchdog.py` |
| `src/ingestion/`, `src/processing/` | `venv/`, `exports/`, `models/` |
| `src/ml/`, `src/monitoring/heartbeat.py` | `.env`, `.env.example` |

Las credenciales se inyectan via variables de entorno en `manifest.yml` (o CF environment settings en producción).

### Comando de despliegue

```bash
# Desde C:\proyectos_programacion\rpc3\3RPC\
cf push
```

---

## 9. Configuración y variables de entorno

Todas las variables se leen en `config.py` via `python-dotenv`. En desarrollo se usa `.env`; en CF se definen en `manifest.yml` o via `cf set-env`.

| Variable | Descripción | Obligatoria |
|---|---|---|
| `API_BASE_URL` | URL base de la API de logs | Sí |
| `API_TOKEN` | Token Bearer de autenticación | Sí |
| `HANA_HOST` | Host de SAP HANA Cloud | Sí |
| `HANA_PORT` | Puerto (default: 443) | No |
| `HANA_USER` | Usuario de HANA | Sí |
| `HANA_PASS` | Contraseña de HANA | Sí |
| `HANA_SCHEMA` | Schema de trabajo | Sí |
| `MAX_PAGES` | Límite de páginas a descargar (0 = sin límite) | No |
| `MIN_TRAINING_HOURS` | Horas mínimas de datos antes de activar ML (default: 24) | No |
| `CF_API` | Endpoint de CF (solo watchdog) | Watchdog |
| `CF_USER` / `CF_PASS` | Credenciales CF (solo watchdog) | Watchdog |
| `CF_ORG` / `CF_SPACE` | Organización y espacio CF | Watchdog |
| `CF_APP_NAME` | Nombre de la app en CF (default: 3RPC) | No |
| `UAA_URL` | URL del UAA para token Service Manager | Watchdog |
| `SM_URL` | URL de Service Manager | Watchdog |
| `SM_CLIENT_ID` / `SM_CLIENT_SECRET` | Credenciales Service Manager | Watchdog |
| `HANA_INSTANCE_ID` | ID de la instancia HANA en Service Manager | Watchdog |

---

## 10. Dependencias

| Paquete | Versión | Uso |
|---|---|---|
| `requests` | 2.33.1 | HTTP client para API y Service Manager |
| `python-dotenv` | 1.2.2 | Carga de variables desde `.env` |
| `pandas` | 2.2.3 | Manipulación de DataFrames |
| `numpy` | 1.26.4 | Cálculos numéricos y feature engineering |
| `hdbcli` | 2.28.20 | Driver oficial SAP HANA Cloud |
| `scikit-learn` | 1.6.1 | Isolation Forest + StandardScaler |
| `river` | 0.21.2 | Half-Space Trees (streaming) |
| `joblib` | 1.4.2 | Serialización de modelos sklearn |

---
