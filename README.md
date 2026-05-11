# 3RPC — Real-time Risk & Response Pipeline for SAP

Pipeline de detección de anomalías en tiempo cuasi-real para logs de una plataforma SAP. Ingesta logs cada 30 minutos desde una API REST, los almacena en SAP HANA Cloud y aplica dos modelos de ML en paralelo para detectar ataques, degradaciones y comportamientos anómalos.

---

## ¿Qué hace el sistema?

1. **Ingesta** — Descarga logs paginados de la API cada 30 minutos (paralelismo por página)
2. **Transforma** — Normaliza, separa en logs de sistema vs LLM y detecta eventos de seguridad
3. **Almacena** — Carga a SAP HANA Cloud via UPSERT idempotente; buffer local CSV ante caídas
4. **Detecta** — Isolation Forest (baseline 24h) + Half-Space Trees (streaming incremental) en paralelo
5. **Alerta** — POST a `/alert` con categoría de amenaza, severidad y métricas clave

**Categorías de amenaza detectadas:** DDoS, Brute Force, LLM Prompt Injection, Server Overload (5xx), Geographic Concentration, Reconnaissance, Security Event Escalation, LLM Degradation, Anomalous LLM Cost, Unusual Statistical Pattern.

---

## Arquitectura rápida

```
API REST  →  preprocessing  →  CSV local (buffer)  →  HANA Cloud
                                                            │
                                              build_features (43 vars, 5-min buckets)
                                                            │
                                            ┌───────────────┴───────────────┐
                                     IsolationForest               HalfSpaceTrees
                                      (batch, 24h)               (streaming, online)
                                            └───────────────┬───────────────┘
                                                     classify_type()
                                                            │
                                                  HANA: ANOMALIES  +  POST /alert
```

> Para la arquitectura completa con tablas HANA, parámetros de modelos y diagramas de recuperación, ver [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Estructura del proyecto

```
3RPC/
├── main.py            # Entrypoint en Cloud Foundry (ETL + ML combinados)
├── config.py          # Lee todas las variables desde .env
├── pipeline.py        # ETL standalone (uso local/debug)
├── ml_pipeline.py     # ML standalone (uso local/debug)
├── src/
│   ├── ingestion/     # api_client.py, hana_client.py
│   ├── processing/    # preprocessing.py
│   ├── ml/            # features, detector, streaming_detector, versioning, alert_sender
│   ├── monitoring/    # heartbeat.py (CF), watchdog.py (servidor físico)
│   └── dashboard/     # app.py — Streamlit (solo local)
├── manifest.yml       # Configuración Cloud Foundry
├── .env.example       # Plantilla de variables de entorno
└── requirements.txt
```

---

## Inicio rápido

### 1. Clonar e instalar

```bash
git clone <url-del-repo>
cd 3RPC
python -m venv venv

# Windows
venv\Scripts\activate
# Mac / Linux
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configurar credenciales

```bash
cp .env.example .env
```

Edita `.env` con los valores reales. **Nunca commitees `.env`** — ya está en `.gitignore`.

```env
API_BASE_URL=https://sap-api-b2.679186.xyz
API_TOKEN=tu_token_aqui

HANA_HOST=tu-instancia.hna1.prod-us10.hanacloud.ondemand.com
HANA_PORT=443
HANA_USER=DBADMIN
HANA_PASS=tu_password
HANA_SCHEMA=SOC_LOGS
```

### 3. Correr el pipeline

```bash
# Pipeline completo (ETL + ML) — mismo que corre en CF
python main.py

# Solo ETL
python pipeline.py

# Solo ML (requiere datos ya cargados en HANA)
python ml_pipeline.py

# Dashboard Streamlit (solo local)
streamlit run src/dashboard/app.py

# Watchdog (monitoreo, corre en servidor físico fuera de CF)
python -m src.monitoring.watchdog
```

---

## Despliegue en Cloud Foundry

```bash
cf login -a <CF_API> -u <usuario> -p <password> -o <org> -s <space>
cf push
```

El `manifest.yml` ya está configurado: `python main.py`, 1 GB de memoria, sin ruta HTTP (`no-route: true`).

**Lo que NO sube a CF** (excluido en `.cfignore`): dashboard, watchdog, `venv/`, `exports/`, `models/`, `.env`.

---

## Variables de entorno

| Variable | Descripción | Requerida |
|---|---|---|
| `API_BASE_URL` | URL base de la API de logs | Sí |
| `API_TOKEN` | Token Bearer | Sí |
| `HANA_HOST` | Host de SAP HANA Cloud | Sí |
| `HANA_PORT` | Puerto (default: 443) | No |
| `HANA_USER` / `HANA_PASS` | Credenciales HANA | Sí |
| `HANA_SCHEMA` | Schema de trabajo | Sí |
| `MAX_PAGES` | Páginas a descargar (0 = todas) | No |
| `MIN_TRAINING_HOURS` | Horas de datos para activar ML (default: 24) | No |
| `CF_API`, `CF_USER`, `CF_PASS`, `CF_ORG`, `CF_SPACE` | Solo para el watchdog | Watchdog |
| `UAA_URL`, `SM_URL`, `SM_CLIENT_ID`, `SM_CLIENT_SECRET`, `HANA_INSTANCE_ID` | Reinicio automático de HANA via Service Manager | Watchdog |

Ver `.env.example` para la plantilla completa.

---

## Dependencias principales

| Paquete | Uso |
|---|---|
| `hdbcli` | Driver SAP HANA Cloud |
| `scikit-learn` | Isolation Forest |
| `river` | Half-Space Trees (streaming) |
| `pandas` / `numpy` | Procesamiento de datos |
| `requests` | Cliente HTTP (API + Service Manager) |
| `streamlit` | Dashboard local |

---

## Documentación técnica

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Arquitectura completa: flujo de datos, esquema HANA, parámetros ML, monitoreo, despliegue
