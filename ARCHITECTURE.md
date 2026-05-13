# 3RPC — Reporte Técnico de Arquitectura

**Versión:** 3.0  
**Fecha:** 2026-05-12  
**Autor:** Equipo 3RPC

---

## Índice

1. [Descripción general](#1-descripción-general)
2. [Estructura de directorios](#2-estructura-de-directorios)
3. [Componentes del sistema](#3-componentes-del-sistema)
4. [Pipeline de datos — entrada, transformaciones y carga](#4-pipeline-de-datos--entrada-transformaciones-y-carga)
5. [Módulo de ML — diseño, hiperparámetros y decisiones](#5-módulo-de-ml--diseño-hiperparámetros-y-decisiones)
6. [Esquema de base de datos (HANA)](#6-esquema-de-base-de-datos-hana)
7. [Monitoreo y recuperación](#7-monitoreo-y-recuperación)
8. [Despliegue en Cloud Foundry](#8-despliegue-en-cloud-foundry)
9. [Métricas de producción](#9-métricas-de-producción)
10. [Riesgos técnicos y mitigaciones](#10-riesgos-técnicos-y-mitigaciones)
11. [Configuración y variables de entorno](#11-configuración-y-variables-de-entorno)
12. [Dependencias](#12-dependencias)

---

## 1. Descripción general

**3RPC** es un pipeline de ingesta, procesamiento y detección de anomalías para logs de una plataforma SAP. El sistema recolecta logs desde una API REST cada 30 minutos, los almacena en SAP HANA Cloud y aplica dos modelos de Machine Learning en paralelo para detectar comportamientos anómalos en tiempo cuasi-real.

<img width="1920" height="1080" alt="Arquitectura 3rpc" src="https://github.com/user-attachments/assets/95c37a93-3f79-4157-a5f2-47c03a86b744" />

### Capacidades principales

| Capacidad | Descripción |
|---|---|
| Ingesta automática | Descarga paginada paralela desde API REST con detección de ventana temporal |
| Buffer ante fallos | Cola local JSON ante caídas de HANA; recovery idempotente via UPSERT |
| Detección de anomalías | Isolation Forest (batch, 24h baseline) + Half-Space Trees (streaming, incremental) |
| Clasificación de amenazas | 10 categorías: DDoS, Brute Force, LLM Prompt Injection, 5xx Overload, etc. |
| Alertas | POST a `/alert` en la API con mensaje estructurado ≤ 300 caracteres |
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
│   ├── processing/
│   │   └── preprocessing.py   # Normalización, split y detección de eventos de seguridad
│   ├── ml/
│   │   ├── features.py        # Feature engineering (43 variables, buckets de 5 min)
│   │   ├── detector.py        # Isolation Forest con clasificación de tipo
│   │   ├── streaming_detector.py  # Half-Space Trees incremental
│   │   ├── versioning.py      # Serialización versionada de modelos
│   │   └── alert_sender.py    # Envío de alertas a la API
│   └── monitoring/
│       ├── heartbeat.py       # Hilo daemon: pulso a HANA cada 60 s
│       └── watchdog.py        # Proceso externo: monitoreo y recovery automático
│
├── exports/                   # CSVs locales (buffer; gitignored)
└── models/                    # Modelos serializados + estado HST (gitignored)
```

---

## 3. Componentes del sistema

### 3.1 `main.py` — Pipeline principal

**Qué hace:** Proceso único que combina ETL y ML en un ciclo continuo. Es el único entrypoint desplegado en Cloud Foundry.

**Por qué un proceso unificado:** Separar ETL y ML en dos procesos independientes requeriría coordinación (señales, colas) y doble conexión a HANA. Al unirlos, el batch recién ingestado está disponible en memoria para el scoring ML sin una consulta adicional, reduciendo latencia y complejidad operacional.

**Flujo por ciclo:**
1. Duerme hasta el próximo slot (`:00` o `:30` exactos)
2. Detecta cambio de ventana en `/info` — polling con backoff `5 → 10 → 30 → 60 s`
3. Drena la cola de pendientes si hay batches fallidos anteriores
4. ETL: descarga → transformación → CSV local → HANA
5. ML: features → IForest + HST → classify → HANA + alerta
6. Persiste estado del HST y número de ciclo en disco

**Conexiones:** consume `src/ingestion`, `src/processing`, `src/ml`, `src/monitoring/heartbeat`.

---

### 3.2 `src/ingestion/api_client.py`

**Qué hace:** Descarga todos los logs de la ventana activa con paralelismo por página.

**Por qué `ThreadPoolExecutor`:** La descarga es I/O-bound (red). El paralelismo con hilos es suficiente y más simple que `asyncio` para este caso. Se evita la complejidad de un event loop en un proceso que también hace operaciones síncronas de HANA.

**Fragmento clave:**
```python
with ThreadPoolExecutor(max_workers=min(total_pages, 8)) as executor:
    futures = {executor.submit(fetch_page, p): p for p in range(1, total_pages + 1)}
    for future in as_completed(futures):
        page, data = future.result()
        all_records.extend(data)
```

**Conexiones:** llamado por `main.py` y `pipeline.py`. Depende de `config.py` para URL y token.

| Endpoint | Uso |
|---|---|
| `GET /info` | `window_start`, `window_end`, `total_pages`, `total_records` |
| `GET /logs/current?page=N` | Registros paginados de la ventana activa |

---

### 3.3 `src/ingestion/hana_client.py`

**Qué hace:** Gestiona conexión a SAP HANA Cloud y carga UPSERT idempotente.

**Por qué UPSERT y no INSERT:** El pipeline puede reiniciarse en cualquier momento (CF crash, deploy, watchdog restart). Si usara INSERT, los reinicios duplicarían datos. UPSERT con `WITH PRIMARY KEY` garantiza que re-ejecutar el mismo batch sea inocuo.

**Por qué SAP HANA Cloud:** El cliente SAP opera en BTP; HANA es el estándar de almacenamiento analítico del ecosistema SAP. Su motor columnar permite queries de agregación sobre millones de filas sin índices adicionales.

**Fragmento clave:**
```python
cursor.executemany(f"""
    UPSERT "{HANA_SCHEMA}"."SYSTEM_LOGS"
    ("_id","timestamp","sourceip",...)
    VALUES (?,?,?,...)
    WITH PRIMARY KEY
""", rows)
conn.commit()
```

---

### 3.4 `src/processing/preprocessing.py`

**Qué hace:** Transforma el JSON crudo de la API en DataFrames listos para HANA y ML.

**Transformaciones aplicadas:**
1. `build_dataframe()` — normaliza timestamps a UTC, convierte tipos numéricos, expande campos anidados
2. `split_by_type()` — separa por `logtype`: `{INFO,WARNING,ERROR,AUDIT,SECURITY,PERF,DEBUG}` → `SYSTEM_LOGS`; `{LLM_REQUEST,LLM_ERROR,LLM_TIMEOUT}` → `LLM_LOGS`
3. `flag_security_events()` — busca patrones en `event_description` (regex) y setea `is_security_event=1`

**Conexiones:** recibe registros crudos de `api_client`, entrega DataFrames a `hana_client` y a `features.py`.

---

## 4. Pipeline de datos — entrada, transformaciones y carga

### 4.1 Esquema de entrada (JSON crudo de la API)

```json
{
  "_id": "abc123def456",
  "timestamp": "2026-05-11T14:35:22Z",
  "logtype": "ERROR",
  "sourceip": "36.109.47.72",
  "port_service": "443/HTTPS",
  "http_status_code": 429,
  "is_security_event": false,
  "event_description": "Rate limit exceeded from IP block",
  "macro_region": "APAC",
  "sap_app_env": "production",
  "_score": 0.82,
  "headers_http_request_method": "POST",
  "llm_model_id": null,
  "llm_cost_usd": null,
  "llm_response_time_ms": null,
  "llm_total_tokens": null,
  "llm_status": null,
  "llm_finish_reason": null
}
```

### 4.2 Transformaciones paso a paso

```
JSON crudo (lista de registros)
        │
        ▼  build_dataframe()
- pd.json_normalize() → DataFrame plano
- timestamp → pd.to_datetime(utc=True)
- http_status_code → pd.to_numeric(errors='coerce')
- _score → float, fillna(0.5)
        │
        ▼  split_by_type()
- logtype in VALID_SYS_LOGTYPES  → df_system
- logtype in VALID_LLM_LOGTYPES  → df_llm
- Filas con logtype desconocido   → descartadas
        │
        ▼  flag_security_events()
- Regex sobre event_description
- is_security_event = 1 si match
        │
        ▼  Filtros por columnas
- df_llm: drop ['sourceip','http_status_code']
- df_system: drop columnas 'llm_*'
        │
        ▼  _append_csv()           [buffer local]
- pd.concat + drop_duplicates(subset=['_id'])
        │
        ▼  UPSERT a HANA
- SYSTEM_LOGS  (df_system)
- LLM_LOGS     (df_llm)
```

### 4.3 Flujo completo ETL → ML

```
API REST (/info, /logs/current)
        │
        ▼ fetch_all_logs()          [src/ingestion/api_client.py]
  JSON paginado paralelo
        │
        ▼ build_dataframe()         [src/processing/preprocessing.py]
  DataFrame normalizado
        │
        ├──▶ split_by_type() + flag_security_events()
        │         │
        │    ┌────┴────┐
        │    ▼         ▼
        │ df_system  df_llm
        │    │         │
        ▼    ▼         ▼
  exports/LOGS_SYSTEM.csv          [buffer local permanente]
  exports/LOGS_LLM.csv
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

## 5. Módulo de ML — diseño, hiperparámetros y decisiones

### 5.1 Feature Engineering (`src/ml/features.py`)

**Por qué buckets de 5 minutos:** Es el balance entre granularidad y ruido. Buckets de 1 minuto tienen muy pocos eventos para calcular tasas estadísticamente estables. Buckets de 15 minutos ocultan spikes cortos (un DDoS de 3 minutos se diluye). Con ~500–600 requests por ventana de 30 minutos, los buckets de 5 minutos tienen ~80–100 requests en promedio — suficiente para calcular tasas robustas.

Los logs se agrupan en **buckets de 5 minutos**. Para cada bucket se calculan **43 variables**:

| Categoría | Variables |
|---|---|
| Volumen e IPs | `n_sys_requests`, `n_unique_ips`, `top_ip_share` |
| HTTP status | `error_rate`, `client_error_rate`, `server_error_rate`, `rate_limit_rate`, `timeout_http_rate` |
| Tipos de log | `pct_error_logtype`, `pct_warning_logtype`, `pct_security_logtype`, `pct_audit_logtype`, `n_unique_logtypes` |
| Seguridad | `security_event_rate`, `n_security_events` |
| Métodos HTTP | `method_entropy`, `pct_post`, `pct_delete` |
| Score de riesgo | `avg_score`, `min_score`, `pct_low_score` |
| Geografía | `n_unique_services`, `n_unique_regions`, `top_region_share`, `pct_production`, `n_unique_envs` |
| LLM volumen | `n_llm_requests`, `llm_error_rate`, `llm_timeout_rate` |
| LLM rendimiento | `avg_llm_latency`, `p95_llm_latency`, `max_llm_latency`, `pct_slow_llm` |
| LLM costo | `avg_llm_cost`, `total_llm_cost`, `max_llm_cost`, `avg_tokens`, `max_tokens` |
| LLM modelos | `n_unique_models`, `pct_content_filter`, `avg_llm_score` |
| Combinadas | `llm_to_sys_ratio`, `total_requests` |

**Fragmento clave — cálculo de features por bucket:**
```python
for b, g in df.groupby("bucket"):
    n = len(g)
    http = g["http_status_code"].dropna()
    rows.append({
        "n_sys_requests":   n,
        "error_rate":       (http >= 400).sum() / n,
        "rate_limit_rate":  (http == 429).sum() / n,
        "server_error_rate":(http >= 500).sum() / n,
        "security_event_rate": (g["is_security_event"] == 1).sum() / n,
        "method_entropy":   _entropy(g["headers_http_request_method"]),
        ...
    })
```

---

### 5.2 Isolation Forest (`src/ml/detector.py`)

**Qué hace:** Detecta anomalías comparando cada bucket de 5 minutos contra el baseline de las últimas 24 horas.

**Por qué Isolation Forest:**
- No requiere datos etiquetados — no tenemos ground truth de ataques históricos confirmados
- Funciona bien con datos tabulares de alta dimensionalidad (43 features)
- Produce un score continuo (no solo binario) que permite ranking de severidad
- Interpretable: `classify_type()` puede calcular qué features se desviaron más (z-scores)
- Alternativas consideradas: DBSCAN (no escala bien con alta dimensionalidad), Autoencoder (más complejo, requiere tuning de arquitectura, menos interpretable)

**Hiperparámetros y justificación:**

| Parámetro | Valor | Justificación |
|---|---|---|
| `n_estimators` | 150 | Por encima de 100 los scores se estabilizan; 150 da varianza mínima sin costo computacional significativo |
| `contamination` | 0.05 | Asumimos que ~5% del tráfico es anómalo. En producción el p5 del score de entrenamiento actúa como umbral dinámico |
| `max_features` | 1.0 | Todas las features; con 43 variables el subsampling aleatorio por defecto ya introduce suficiente diversidad |
| `random_state` | no fijado | Se re-entrena cada ciclo; la aleatoriedad es deseable para evitar sobreajuste a un seed |
| Ventana de entrenamiento | 24 h | Captura el ciclo diario completo. Menos de 12h es insuficiente para estabilizar la distribución; más de 48h hace el baseline demasiado rígido ante cambios legítimos |
| Re-entrenamiento | cada 2 ciclos (~1 h) | Frecuencia suficiente para adaptarse a cambios graduales sin re-entrenar en cada ingesta (costoso) |
| Normalización | `StandardScaler` | IForest no es sensible a escala, pero escalar mejora la interpretación de z-scores en `classify_type()` |

**Clasificación de amenazas — lógica de `classify_type()`:**

Para cada anomalía detectada, se calculan los z-scores de cada feature contra el baseline de entrenamiento. La categoría se asigna por el patrón de features más desviadas (`SPIKE_SIGMA = 2.5`):

| Categoría | Feature principal | Umbral |
|---|---|---|
| DDoS / Traffic Flooding | `n_sys_requests` + `rate_limit_rate` | z > 2.5 ambas |
| Brute Force | `n_unique_ips` + `pct_post` | z > 2.5 ambas |
| LLM Prompt Injection | `pct_content_filter` | z > 2.5 |
| Server Overload (5xx) | `server_error_rate` | z > 2.5 |
| Geographic Concentration | `top_region_share` | z > 2.5 |
| Reconnaissance / Scanning | `n_unique_services` + volumen bajo | z > 2.5 + n < media |
| Security Event Escalation | `security_event_rate` | z > 2.5 |
| LLM Service Degradation | `llm_error_rate` + `avg_llm_latency` | z > 2.5 ambas |
| Anomalous LLM Cost | `total_llm_cost` o `max_llm_cost` | z > 2.5 cualquiera |
| Unusual Statistical Pattern | ninguna categoría específica | fallback |

---

### 5.3 Half-Space Trees (`src/ml/streaming_detector.py`)

**Qué hace:** Detector incremental que aprende de cada bucket nuevo sin re-entrenar desde cero.

**Por qué Half-Space Trees:**
- IForest necesita acumular 24h de datos antes de poder entrenar. En las primeras horas del sistema, HST ya puede detectar cambios bruscos relativos a lo que acaba de ver
- HST es resistente a concept drift lento porque usa una ventana deslizante interna (no acumula historia indefinida)
- Se complementa con IForest: IForest detecta anomalías contra el baseline histórico; HST detecta cambios bruscos recientes. Un bucket anómalo para ambos tiene alta confianza
- Librería `river` es la implementación de referencia para ML online en Python

**Hiperparámetros y justificación:**

| Parámetro | Valor | Justificación |
|---|---|---|
| `n_trees` | 25 | Menos árboles que IForest porque actualiza online; 25 balancea velocidad y estabilidad |
| `height` | 8 | Define la profundidad del árbol (2^8 = 256 particiones posibles). Suficiente para 12 features |
| `window_size` | 8 buckets (~40 min) | Memoria de ~40 minutos de tráfico reciente. Menos memoria = más reactivo a spikes pero más falsos positivos |
| `threshold` | 0.7 | Score HST normalizado [0,1]; 0.7 captura el 30% superior de anomalías sin ser demasiado sensible |
| Features | 12 (subconjunto) | Solo features de alta señal para detección rápida: volumen, error rates, seguridad, LLM críticos |
| Warmup | ≥ 4h (8 buckets × ~30 min/ingesta) | HST no emite alertas hasta haber visto suficientes buckets para establecer una distribución de referencia |

**Persistencia del estado HST:**
```python
# Al finalizar cada ciclo:
import pickle
with open("models/hst_state.pkl", "wb") as f:
    pickle.dump(hst, f)

# Al arrancar:
with open("models/hst_state.pkl", "rb") as f:
    hst = pickle.load(f)
# hst.n_learned buckets ya aprendidos — no hay re-warmup
```

---

### 5.4 Combinación de modelos y lógica de confianza

**Decisión de diseño — por qué dos modelos:**

| Modelo | Fortaleza | Debilidad |
|---|---|---|
| IForest | Detecta anomalías contra baseline histórico de 24h | Ciego a cambios bruscos muy recientes si no divergen mucho del baseline acumulado |
| HST | Detecta cambios bruscos en los últimos ~40 min | Sin warmup inicial; puede dar falsos positivos si el tráfico tiene variabilidad natural alta |

Al combinarlos, el tradeoff es favorable: los falsos positivos de uno raramente coinciden con los del otro.

```
IForest flagea  +  HST flagea    →  ALTA CONFIANZA  (hst_confirmed=True)
IForest flagea  (HST no)         →  Anomalía histórica — posible drift lento
HST flagea      (IForest no)     →  Cambio brusco reciente — posible transiente
```

---

### 5.5 Persistencia de modelos

```
models/
├── model_v1.pkl         # IForest serializado (joblib)
├── model_v1_meta.json   # {training_hours, n_features, bucket_size, timestamp}
├── hst_state.pkl        # Estado completo del HST (pickle)
└── ml_state.json        # {cycle, last_scored_until, saved_at}
```

Al reiniciar CF, el pipeline restaura el HST y el estado ML evitando re-warmup y gaps de scoring.

---

## 6. Esquema de base de datos (HANA)

### `SYSTEM_LOGS`

| Columna | Tipo | Descripción |
|---|---|---|
| `_id` | `NVARCHAR(64)` PK | Identificador único del log |
| `timestamp` | `TIMESTAMP` | Timestamp del evento (UTC) |
| `logtype` | `NVARCHAR(30)` | INFO, WARNING, ERROR, AUDIT, SECURITY, PERF, DEBUG |
| `sourceip` | `NVARCHAR(50)` | IP de origen |
| `port_service` | `NVARCHAR(50)` | Servicio/puerto destino |
| `http_status_code` | `INTEGER` | Código HTTP de respuesta |
| `is_security_event` | `TINYINT` | Flag 0/1 |
| `event_description` | `NCLOB` | Descripción del evento |
| `macro_region` | `NVARCHAR(50)` | Región geográfica |
| `sap_app_env` | `NVARCHAR(30)` | Entorno SAP |
| `_score` | `DECIMAL(10,6)` | Score de riesgo original de la API |

### `LLM_LOGS`

| Columna | Tipo | Descripción |
|---|---|---|
| `_id` | `NVARCHAR(64)` PK | Identificador único |
| `timestamp` | `TIMESTAMP` | Timestamp de la llamada (UTC) |
| `llm_model_id` | `NVARCHAR(100)` | Identificador del modelo LLM |
| `llm_cost_usd` | `DECIMAL(10,6)` | Costo en USD |
| `llm_response_time_ms` | `INTEGER` | Latencia en ms |
| `llm_total_tokens` | `INTEGER` | Total de tokens procesados |
| `llm_status` | `NVARCHAR(30)` | success, error, timeout |
| `llm_finish_reason` | `NVARCHAR(50)` | stop, content_filter, length, etc. |
| `sap_llm_response_size` | `INTEGER` | Tamaño de la respuesta |

### `ANOMALIES`

| Columna | Tipo | Descripción |
|---|---|---|
| `anomaly_id` | `NVARCHAR(64)` PK | UUID generado al detectar |
| `detected_at` | `TIMESTAMP` | Momento de detección |
| `bucket_start` | `TIMESTAMP` | Inicio del bucket de 5 min anómalo |
| `anomaly_type` | `NVARCHAR(30)` | SPIKE, MULTI_BUCKET, CATEGORIZATION |
| `severity` | `NVARCHAR(10)` | HIGH / MEDIUM |
| `anomaly_score` | `DECIMAL(10,6)` | Score IForest (más negativo = más anómalo) |
| `n_requests` | `INTEGER` | Requests en el bucket |
| `n_unique_ips` | `INTEGER` | IPs únicas en el bucket |
| `error_rate` | `DECIMAL(10,4)` | Tasa de errores HTTP |
| `top_ip` | `NVARCHAR(50)` | IP más activa del bucket |
| `reason` | `NVARCHAR(500)` | Explicación legible |
| `attack_category` | `NVARCHAR(100)` | Categoría de amenaza |
| `details_json` | `NCLOB` | JSON: top_deviations, feature_snapshot, log_ids |

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

Hilo daemon dentro de `main.py`. Cada 60 segundos hace UPSERT en `PIPELINE_HEARTBEAT`. Si el proceso muere, el pulso se detiene — el watchdog lo detecta.

**Por qué hilo daemon y no proceso separado:** Un proceso separado requeriría IPC o sincronización de estado. Como hilo daemon, accede directamente al estado del pipeline principal (`cycle`, `last_window`) sin overhead. Al morir el proceso principal, el daemon muere automáticamente — no hay zombies.

### 7.2 Watchdog (`src/monitoring/watchdog.py`)

Proceso independiente en **servidor físico** (fuera de CF). Consulta `PIPELINE_HEARTBEAT` cada 60 segundos.

```
Ciclo watchdog:
  ┌─ HANA no responde ──────────────────────────────────────────┐
  │  → restart_hana() via Service Manager API (PATCH)            │
  │  → Polling estado cada 1 min durante 5 min                   │
  │  → Reintenta hasta MAX_RESTART_RETRIES=3                     │
  └──────────────────────────────────────────────────────────────┘
  ┌─ HANA OK, pulso > 180 s ────────────────────────────────────┐
  │  → restart_cf_pipeline() via CF CLI                          │
  │  → cf login → cf restart 3RPC                               │
  │  → Polling estado CF cada 1 min durante 5 min               │
  └──────────────────────────────────────────────────────────────┘
  ┌─ HANA OK, pulso reciente ───────────────────────────────────┐
  │  → Log estado y esperar 60 s                                 │
  └──────────────────────────────────────────────────────────────┘
```

**Por qué servidor físico y no otro proceso en CF:** CF puede caerse entero (deploy, quota, outage). El watchdog debe estar en infraestructura completamente independiente para poder detectar caídas de CF y reaccionar.

### 7.3 Recovery ante fallos de HANA

**Por qué `pending_queue.json` y no una base de datos local:** SQLite añade dependencia y overhead. JSON es portable, legible y suficiente para el volumen de datos (máximo unos pocos batches de 30 min). Si el sistema falla repetidamente, el archivo crece y es inspeccionable directamente.

```
HANA cae durante ETL
        │
        ▼ _enqueue_pending()
        │  Serializa batch en exports/pending_queue.json
        │
HANA vuelve (ciclo siguiente)
        │
        ▼ _drain_pending_queue()
        │  UPSERT de todos los batches pendientes
        │  Elimina pending_queue.json si éxito total
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

- `no-route: true` — proceso background sin endpoint HTTP expuesto
- `health-check-type: process` — CF verifica que el proceso esté vivo, no un HTTP endpoint
- `instances: 1` — instancia única deliberada; múltiples instancias descargarían la misma ventana de la API duplicando datos

### Qué sube a CF

| Incluido | Excluido (`.cfignore`) |
|---|---|
| `main.py`, `pipeline.py`, `ml_pipeline.py` | `src/monitoring/watchdog.py` |
| `config.py`, `requirements.txt` | `venv/`, `exports/`, `models/` |
| `src/ingestion/`, `src/processing/`, `src/ml/` | `.env`, `.env.example` |
| `src/monitoring/heartbeat.py` | `export_csv.py`, `verify_anomalies.py` |

---

## 9. Métricas de producción

Datos reales de HANA tras 19 días en producción:

| Métrica | Valor |
|---|---|
| Total anomalías detectadas | 1,134 |
| Días en producción | 19 |
| Promedio de detecciones/día | 54 |
| Pico máximo en un día | 578 (7 de mayo) |
| Alertas generadas en < 30 min | 44% |
| Intervenciones manuales | 0 |

**Distribución por categoría:**

| Categoría | Detecciones | % |
|---|---|---|
| DDoS / Flooding de Tráfico | 481 | 42% |
| Costo LLM Anómalo | 262 | 23% |
| Patrón Estadístico Inusual | 136 | 12% |
| Escalada de Eventos de Seguridad | 99 | 9% |
| Degradación de Servicio LLM | 44 | 4% |
| Inyección de Prompt LLM | 42 | 4% |
| Sobrecarga de Servidor (5xx) | 25 | 2% |
| Concentración Geográfica | 24 | 2% |
| Otros | 21 | 2% |

**Distribución por tipo de anomalía:**

| Tipo | Descripción | Detecciones |
|---|---|---|
| `MULTI_BUCKET` | Actividad sostenida en múltiples buckets consecutivos | 716 (63%) |
| `CATEGORIZATION` | Spike en features específicas de una categoría | 402 (35%) |
| `SPIKE` | Spike aislado en volumen o error rate | 16 (2%) |

**Nota sobre MTTD:** El sistema re-evalúa la ventana completa de 24h en cada ciclo. El MTTD para eventos nuevos (misma ventana de ingesta) es ≤ 30 minutos. El MTTD promedio incluye re-detecciones de buckets históricos dentro de la ventana de entrenamiento.

---

## 10. Riesgos técnicos y mitigaciones

| Riesgo | Impacto | Probabilidad | Mitigación |
|---|---|---|---|
| **Baseline contamination** — si una amenaza sostenida dura > 24h, el modelo la aprende como normal y deja de alertar | Alto | Media | Monitorear ausencia prolongada de alertas; agregar umbrales absolutos en `classify_type()` para features críticas |
| **HST warmup ciego** — en las primeras ~4h tras un reinicio, HST no emite alertas | Medio | Alta (cada reinicio) | IForest sigue activo durante el warmup; las anomalías sostenidas siguen detectándose |
| **HANA auto-stop** — SAP HANA Cloud free tier se apaga si está inactivo | Alto | Media | Watchdog externo detecta falta de conexión y llama a Service Manager para reencenderla |
| **Instancia única CF sin HA** — si el contenedor CF muere, hay un gap de ingesta | Medio | Baja | Watchdog detecta ausencia de heartbeat en 3 min y reinicia; CSV buffer recupera datos al volver |
| **Disco efímero CF** — `models/` y `exports/` se pierden en cada deploy | Bajo | Alta (cada deploy) | HST re-entra en warmup; IForest re-entrena en el primer ciclo. Los CSVs se reconstruyen desde HANA via `startup_recovery` |
| **Token de API expirado** | Alto | Baja | El pipeline lanza excepción, el ciclo falla y reintenta; alertar si hay N ciclos consecutivos fallidos |
| **Contaminación del 5% demasiado agresiva** | Medio | Media | Todos los buckets tienen `severity=HIGH` actualmente; revisar calibración de `contamination` o añadir MEDIUM para anomalías de baja magnitud |
| **Rate limit en `POST /alert`** | Bajo | Baja | `alert_sender.py` captura la excepción y loguea; el ciclo ML continúa |

---

## 11. Configuración y variables de entorno

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
| `MIN_TRAINING_HOURS` | Horas mínimas antes de activar ML (default: 24) | No |
| `CF_API` / `CF_USER` / `CF_PASS` | Credenciales CF — solo watchdog | Watchdog |
| `CF_ORG` / `CF_SPACE` / `CF_APP_NAME` | Organización y espacio CF | Watchdog |
| `UAA_URL` / `SM_URL` | Service Manager — solo watchdog | Watchdog |
| `SM_CLIENT_ID` / `SM_CLIENT_SECRET` | Credenciales Service Manager | Watchdog |
| `HANA_INSTANCE_ID` | ID de instancia HANA en Service Manager | Watchdog |

---

## 12. Dependencias

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
