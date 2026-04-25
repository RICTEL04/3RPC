import json

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from hdbcli import dbapi
from config import HANA_HOST, HANA_PORT, HANA_USER, HANA_PASS, HANA_SCHEMA

st.set_page_config(
    page_title="3RPC — SAP Security Logs",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_data(ttl=60)
def load_table(query: str) -> pd.DataFrame:
    conn = dbapi.connect(
        address=HANA_HOST, port=HANA_PORT,
        user=HANA_USER, password=HANA_PASS,
        encrypt=True, sslValidateCertificate=False,
    )
    df = pd.read_sql(query, conn)
    conn.close()
    df.columns = [c.lower() for c in df.columns]
    return df


def load_system() -> pd.DataFrame:
    return load_table(f"""
        SELECT "_id","timestamp","sourceip","port_service","event_description",
               "status","logtype","region_id","region_name","region_code",
               "macro_region","_score","headers_http_request_method",
               "sap_app_env","http_status_code","is_security_event"
        FROM "{HANA_SCHEMA}"."SYSTEM_LOGS"
        ORDER BY "timestamp" DESC
    """)


def load_llm() -> pd.DataFrame:
    return load_table(f"""
        SELECT "_id","timestamp","port_service","event_description","status",
               "logtype","region_id","region_name","region_code","macro_region",
               "sap_llm_response_time","sap_llm_response_size","llm_cost_usd",
               "_score","headers_http_request_method","llm_model_id","sap_app_env",
               "llm_finish_reason","llm_temperature","llm_response_time_ms",
               "llm_total_tokens","llm_status","llm_prompt"
        FROM "{HANA_SCHEMA}"."LLM_LOGS"
        ORDER BY "timestamp" DESC
    """)


@st.cache_data(ttl=60)
def load_anomalies(hours: int) -> pd.DataFrame:
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        df = load_table(f"""
            SELECT "anomaly_id","detected_at","bucket_start","anomaly_type",
                   "severity","anomaly_score","n_requests","n_unique_ips",
                   "error_rate","top_ip","reason","details_json","attack_category"
            FROM "{HANA_SCHEMA}"."ANOMALIES"
            WHERE "detected_at" >= '{since}'
            ORDER BY "bucket_start" ASC
        """)
    except Exception:
        # attack_category column may not exist yet on older schema
        df = load_table(f"""
            SELECT "anomaly_id","detected_at","bucket_start","anomaly_type",
                   "severity","anomaly_score","n_requests","n_unique_ips",
                   "error_rate","top_ip","reason","details_json"
            FROM "{HANA_SCHEMA}"."ANOMALIES"
            WHERE "detected_at" >= '{since}'
            ORDER BY "bucket_start" ASC
        """)
        df["attack_category"] = "N/A"
    for col in ("detected_at", "bucket_start"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)
    return df


# ── Sidebar ────────────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ 3RPC Dashboard")
st.sidebar.markdown("**SAP Security Log Monitor**")
st.sidebar.divider()

view = st.sidebar.radio("Vista", ["Anomalias ML", "System Logs", "LLM Logs", "Resumen General"])

if st.sidebar.button("🔄 Actualizar datos"):
    st.cache_data.clear()

st.sidebar.divider()
st.sidebar.caption("Datos en tiempo real desde SAP HANA Cloud · Se refresca cada 60 s")


# ── Carga de datos ─────────────────────────────────────────────────────────────
with st.spinner("Cargando datos desde HANA Cloud…"):
    try:
        df_sys = load_system()
        df_llm = load_llm()
    except Exception as e:
        st.error(f"Error al conectar con HANA Cloud: {e}")
        st.stop()

for df in (df_sys, df_llm):
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)


# ── Filtros por sidebar ────────────────────────────────────────────────────────
def sidebar_filters(df: pd.DataFrame, prefix: str):
    if df.empty or "timestamp" not in df.columns:
        return df

    min_ts = df["timestamp"].min().date()
    max_ts = df["timestamp"].max().date()
    date_range = st.sidebar.date_input(
        "Rango de fechas", value=(min_ts, max_ts),
        min_value=min_ts, max_value=max_ts, key=f"date_{prefix}",
    )
    if len(date_range) == 2:
        df = df[
            (df["timestamp"].dt.date >= date_range[0]) &
            (df["timestamp"].dt.date <= date_range[1])
        ]

    if "macro_region" in df.columns:
        regions = ["Todas"] + sorted(df["macro_region"].dropna().unique().tolist())
        sel_region = st.sidebar.selectbox("Región", regions, key=f"region_{prefix}")
        if sel_region != "Todas":
            df = df[df["macro_region"] == sel_region]

    if "logtype" in df.columns:
        types = ["Todos"] + sorted(df["logtype"].dropna().unique().tolist())
        sel_type = st.sidebar.selectbox("Tipo de log", types, key=f"type_{prefix}")
        if sel_type != "Todos":
            df = df[df["logtype"] == sel_type]

    return df


# ══════════════════════════════════════════════════════════════════════════════
# VISTA: ANOMALIAS ML
# ══════════════════════════════════════════════════════════════════════════════
if view == "Anomalias ML":
    st.title("🔍 Deteccion de Anomalias — ML Pipeline")

    st.sidebar.divider()
    hours_back = st.sidebar.slider("Ventana de analisis (horas)", 1, 168, 24, key="anom_hours")

    with st.spinner("Cargando anomalias desde HANA…"):
        df_anom = load_anomalies(hours_back)

    if df_anom.empty:
        st.info("No hay anomalias detectadas en el periodo seleccionado. "
                "Ejecuta `ml_pipeline.py` para generar detecciones.")
        st.stop()

    # ── KPIs ──────────────────────────────────────────────────────────────────
    high   = int((df_anom["severity"] == "HIGH").sum())
    medium = int((df_anom["severity"] == "MEDIUM").sum())
    low    = int((df_anom["severity"] == "LOW").sum())
    worst  = float(df_anom["anomaly_score"].min())

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Anomalias",    len(df_anom))
    c2.metric("Alta Severidad",     high,   delta=str(high),   delta_color="inverse")
    c3.metric("Media Severidad",    medium, delta=str(medium), delta_color="off")
    c4.metric("Baja Severidad",     low,    delta=str(low),    delta_color="off")
    c5.metric("Peor Score",         f"{worst:.4f}", delta_color="inverse")

    st.divider()

    # ── Grafica principal: volumen + marcadores de anomalias ──────────────────
    st.subheader("📈 Timeline de actividad y anomalias detectadas")

    gran_anom = st.select_slider(
        "Granularidad del volumen", options=["5min", "10min", "30min", "1h"],
        value="10min", key="gran_anom",
    )

    # Volumen de fondo (sys + llm)
    ts_sys = df_sys[["timestamp"]].copy(); ts_sys["src"] = "Sistema"
    ts_llm = df_llm[["timestamp"]].copy(); ts_llm["src"] = "LLM"
    ts_all = pd.concat([ts_sys, ts_llm], ignore_index=True)
    ts_all["bucket"] = ts_all["timestamp"].dt.floor(gran_anom)
    vol_bg = ts_all.groupby("bucket").size().reset_index(name="count")

    # Colores y símbolos por tipo de anomalia
    TYPE_STYLE = {
        "SPIKE":        {"color": "#EF553B", "symbol": "circle",       "size": 14},
        "MULTI_BUCKET": {"color": "#636EFA", "symbol": "diamond",      "size": 14},
        "CATEGORIZATION":{"color": "#FF7F0E","symbol": "triangle-up",  "size": 12},
    }
    SEV_OPACITY = {"HIGH": 1.0, "MEDIUM": 0.75, "LOW": 0.5}

    fig = go.Figure()

    # Área de volumen total al fondo
    fig.add_trace(go.Scatter(
        x=vol_bg["bucket"], y=vol_bg["count"],
        fill="tozeroy", mode="lines",
        line=dict(color="#888", width=1),
        fillcolor="rgba(136,136,136,0.12)",
        name="Volumen total", hovertemplate="%{x}<br>Logs: %{y}<extra></extra>",
    ))

    # Sombra "Model Context Window" (ultimas TRAINING_HOURS horas)
    if not ts_all.empty and "bucket" in ts_all.columns:
        from datetime import timedelta as _td
        ctx_end   = ts_all["bucket"].max()
        try:
            from ml.features import TRAINING_HOURS as _TH
        except Exception:
            _TH = 24
        ctx_start = ctx_end - _td(hours=_TH)
        max_vol   = int(vol_bg["count"].max()) if not vol_bg.empty else 100
        fig.add_trace(go.Scatter(
            x=[ctx_start, ctx_start, ctx_end, ctx_end],
            y=[0, max_vol * 1.15, max_vol * 1.15, 0],
            fill="toself", mode="none",
            fillcolor="rgba(100,149,237,0.07)",
            name=f"Ventana de entrenamiento ({_TH}h)",
            hoverinfo="skip",
        ))

    # Marcadores de anomalias — un trace por tipo para la leyenda
    for a_type, style in TYPE_STYLE.items():
        subset = df_anom[df_anom["anomaly_type"] == a_type]
        if subset.empty:
            continue
        # altura del marcador = n_requests del bucket (si existe, sino max volumen)
        y_vals = []
        for _, r in subset.iterrows():
            bucket_time = r["bucket_start"]
            nearest = vol_bg.loc[
                (vol_bg["bucket"] - bucket_time).abs().idxmin()
            ] if not vol_bg.empty else None
            y_vals.append(int(nearest["count"]) if nearest is not None else 5)

        opacities = [SEV_OPACITY.get(s, 0.8) for s in subset["severity"]]
        hover = [
            f"<b>{row['anomaly_type']}</b> [{row['severity']}]<br>"
            f"Score: {row['anomaly_score']:.4f}<br>"
            f"Categoria: {row.get('attack_category','')}<br>"
            f"Razon: {str(row['reason'])[:120]}"
            for _, row in subset.iterrows()
        ]

        fig.add_trace(go.Scatter(
            x=subset["bucket_start"], y=y_vals,
            mode="markers",
            marker=dict(
                color=style["color"],
                symbol=style["symbol"],
                size=style["size"],
                opacity=opacities,
                line=dict(width=1, color="white"),
            ),
            name=a_type,
            text=hover, hovertemplate="%{text}<extra></extra>",
        ))

    fig.update_layout(
        xaxis_title="Tiempo (UTC)", yaxis_title="Nº de logs",
        legend=dict(orientation="h", y=1.08, font=dict(size=11)),
        hovermode="closest", height=380,
        margin=dict(t=20, b=40),
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
    )
    st.plotly_chart(fig, use_container_width=True)

    st.caption(
        "Circulo rojo = SPIKE (pico de volumen)  |  "
        "Diamante azul = MULTI_BUCKET (patron sostenido)  |  "
        "Triangulo naranja = CATEGORIZATION (combinacion inusual)  |  "
        "Opacidad refleja severidad"
    )

    st.divider()

    # ── Desgloses ──────────────────────────────────────────────────────────────
    col_l, col_r = st.columns(2)

    with col_l:
        st.subheader("Categorias de ataque detectadas")
        cat_counts = (
            df_anom["attack_category"].fillna("Desconocido")
            .value_counts().reset_index()
        )
        cat_counts.columns = ["categoria", "count"]
        fig_cat = px.bar(
            cat_counts, x="count", y="categoria", orientation="h",
            color="count", color_continuous_scale="Reds",
            labels={"count": "Anomalias", "categoria": ""},
        )
        fig_cat.update_layout(
            coloraxis_showscale=False, yaxis=dict(autorange="reversed"),
            height=300, margin=dict(t=10, b=20),
        )
        st.plotly_chart(fig_cat, use_container_width=True)

    with col_r:
        st.subheader("Distribucion por tipo y severidad")
        pivot = (
            df_anom.groupby(["anomaly_type", "severity"])
            .size().reset_index(name="count")
        )
        sev_order   = ["HIGH", "MEDIUM", "LOW"]
        sev_colors  = {"HIGH": "#EF553B", "MEDIUM": "#FFA15A", "LOW": "#FECB52"}
        fig_sev = px.bar(
            pivot, x="anomaly_type", y="count", color="severity",
            color_discrete_map=sev_colors,
            category_orders={"severity": sev_order},
            labels={"anomaly_type": "Tipo", "count": "Anomalias"},
        )
        fig_sev.update_layout(
            legend_title="Severidad", height=300, margin=dict(t=10, b=20),
        )
        st.plotly_chart(fig_sev, use_container_width=True)

    st.divider()

    # ── Tabla detalle con top deviaciones expandibles ─────────────────────────
    st.subheader("Detalle de anomalias")

    sev_filter = st.multiselect(
        "Filtrar por severidad", ["HIGH", "MEDIUM", "LOW"],
        default=["HIGH", "MEDIUM"], key="sev_filter",
    )
    type_filter = st.multiselect(
        "Filtrar por tipo", df_anom["anomaly_type"].unique().tolist(),
        default=df_anom["anomaly_type"].unique().tolist(), key="type_filter",
    )

    df_show = df_anom[
        df_anom["severity"].isin(sev_filter) &
        df_anom["anomaly_type"].isin(type_filter)
    ].sort_values("anomaly_score")

    for _, row in df_show.iterrows():
        sev_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}.get(row["severity"], "⚪")
        label = (
            f"{sev_icon} **[{row['severity']}] {row['anomaly_type']}** — "
            f"`{str(row['bucket_start'])[:19]}` — "
            f"Score: `{row['anomaly_score']:.4f}` — "
            f"{row.get('attack_category', '')}"
        )
        with st.expander(label, expanded=False):
            st.markdown(f"**Razon:** {row['reason']}")
            st.markdown(
                f"Requests: **{row['n_requests']:,}** | "
                f"IPs unicas: **{row['n_unique_ips']}** | "
                f"Error rate: **{row['error_rate']:.1%}** | "
                f"IP top: `{row.get('top_ip') or 'N/A'}`"
            )

            # Top deviaciones desde details_json
            try:
                details   = json.loads(row.get("details_json") or "{}")
                top_devs  = details.get("top_deviations", [])
            except Exception:
                top_devs = []

            if top_devs:
                st.markdown("**Features mas desviadas del baseline:**")
                dev_df = pd.DataFrame(top_devs)[
                    ["label", "value", "baseline", "z_score", "direction"]
                ].rename(columns={
                    "label": "Feature", "value": "Valor",
                    "baseline": "Baseline", "z_score": "Z-Score",
                    "direction": "Dir",
                })
                dev_df["Z-Score"] = dev_df["Z-Score"].apply(lambda z: f"{z:+.2f}")
                dev_df["Valor"]   = dev_df["Valor"].apply(
                    lambda v: f"{v:.4f}" if isinstance(v, float) else v
                )
                st.dataframe(dev_df, use_container_width=True, hide_index=True)

                # Mini bar chart de z-scores
                z_data = pd.DataFrame([
                    {"feature": d["label"][:35], "z": abs(d["z_score"]),
                     "dir": d["direction"]}
                    for d in top_devs[:8]
                ])
                z_data["color"] = z_data["dir"].map(
                    {"(alto)": "#EF553B", "(bajo)": "#636EFA"}
                ).fillna("#888")
                fig_z = px.bar(
                    z_data, x="z", y="feature", orientation="h",
                    color="dir",
                    color_discrete_map={"(alto)": "#EF553B", "(bajo)": "#636EFA"},
                    labels={"z": "|Z-Score|", "feature": "", "dir": "Direccion"},
                )
                fig_z.update_layout(
                    height=max(200, len(z_data) * 32),
                    margin=dict(t=5, b=5), showlegend=True,
                    yaxis=dict(autorange="reversed"),
                )
                st.plotly_chart(fig_z, use_container_width=True)

            # Tabla de logs relacionados (cluster view para CATEGORIZATION)
            if row["anomaly_type"] == "CATEGORIZATION":
                st.markdown("**Vista de cluster — logs en esta ventana:**")
                sys_ids = details.get("sys_log_ids", [])
                llm_ids = details.get("llm_log_ids", [])
                snap    = details.get("feature_snapshot", {})
                if snap:
                    snap_df = pd.DataFrame(
                        [{"Feature": k, "Valor en ventana": v}
                         for k, v in snap.items() if v is not None]
                    )
                    st.dataframe(snap_df, use_container_width=True, hide_index=True)
                if sys_ids:
                    st.caption(f"IDs de logs sistema en la ventana: {sys_ids[:10]}")
                if llm_ids:
                    st.caption(f"IDs de logs LLM en la ventana: {llm_ids[:10]}")

    if df_show.empty:
        st.info("Ninguna anomalia coincide con los filtros seleccionados.")


# ══════════════════════════════════════════════════════════════════════════════
# VISTA: RESUMEN GENERAL
# ══════════════════════════════════════════════════════════════════════════════
elif view == "Resumen General":
    st.title("📊 Resumen General de Logs")

    total_sys  = len(df_sys)
    total_llm  = len(df_llm)
    sec_events = int(df_sys["is_security_event"].sum()) if "is_security_event" in df_sys.columns else 0
    total_cost = df_llm["llm_cost_usd"].sum() if "llm_cost_usd" in df_llm.columns else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Logs de Sistema", f"{total_sys:,}")
    c2.metric("Logs LLM", f"{total_llm:,}")
    c3.metric("Eventos de Seguridad", f"{sec_events:,}",
              delta=f"{sec_events/total_sys*100:.1f}% del total" if total_sys else None,
              delta_color="inverse")
    c4.metric("Costo LLM Total (USD)", f"${total_cost:,.4f}")

    st.divider()

    # ── Volumen total de logs a lo largo del tiempo ────────────────────────────
    st.subheader("📈 Volumen de logs a lo largo del tiempo")
    if not df_sys.empty or not df_llm.empty:
        granularity = st.select_slider(
            "Granularidad", options=["5min", "10min", "30min", "1h"],
            value="10min", key="gran_overview",
        )
        ts_sys = df_sys[["timestamp"]].copy()
        ts_sys["fuente"] = "Sistema"
        ts_llm = df_llm[["timestamp"]].copy()
        ts_llm["fuente"] = "LLM"
        ts_all = pd.concat([ts_sys, ts_llm], ignore_index=True)
        ts_all["bucket"] = ts_all["timestamp"].dt.floor(granularity)
        vol = ts_all.groupby(["bucket", "fuente"]).size().reset_index(name="count")
        vol_total = ts_all.groupby("bucket").size().reset_index(name="count")

        fig = go.Figure()
        # Área total al fondo
        fig.add_trace(go.Scatter(
            x=vol_total["bucket"], y=vol_total["count"],
            fill="tozeroy", mode="lines",
            line=dict(color="#1f77b4", width=1.5),
            fillcolor="rgba(31,119,180,0.15)",
            name="Total",
        ))
        # Línea por fuente encima
        colors = {"Sistema": "#EF553B", "LLM": "#00CC96"}
        for fuente, grp in vol.groupby("fuente"):
            fig.add_trace(go.Scatter(
                x=grp["bucket"], y=grp["count"],
                mode="lines", name=fuente,
                line=dict(color=colors.get(fuente, "#888"), width=1.5),
            ))
        fig.update_layout(
            xaxis_title="Tiempo", yaxis_title="Nº de logs",
            legend=dict(orientation="h", y=1.05),
            hovermode="x unified", height=300,
            margin=dict(t=10, b=40),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.divider()
    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Distribución por tipo de log — Sistema")
        if not df_sys.empty:
            counts = df_sys["logtype"].value_counts().reset_index()
            counts.columns = ["logtype", "count"]
            fig = px.bar(counts, x="logtype", y="count", color="logtype",
                         color_discrete_sequence=px.colors.qualitative.Safe)
            fig.update_layout(showlegend=False, xaxis_title="", yaxis_title="Registros")
            st.plotly_chart(fig, use_container_width=True)

    with col_b:
        st.subheader("Distribución por tipo de log — LLM")
        if not df_llm.empty:
            counts = df_llm["logtype"].value_counts().reset_index()
            counts.columns = ["logtype", "count"]
            fig = px.pie(counts, names="logtype", values="count",
                         color_discrete_sequence=px.colors.qualitative.Pastel)
            st.plotly_chart(fig, use_container_width=True)

    col_c, col_d = st.columns(2)

    with col_c:
        st.subheader("Top 10 Regiones — Actividad total")
        combined_regions = pd.concat([
            df_sys[["macro_region"]],
            df_llm[["macro_region"]]
        ]).dropna()
        top_regions = combined_regions["macro_region"].value_counts().head(10).reset_index()
        top_regions.columns = ["region", "count"]
        fig = px.bar(top_regions, x="count", y="region", orientation="h",
                     color="count", color_continuous_scale="Blues")
        fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False)
        st.plotly_chart(fig, use_container_width=True)

    with col_d:
        st.subheader("Eventos de seguridad vs normales")
        if "is_security_event" in df_sys.columns:
            seg_df = df_sys["is_security_event"].map({1: "Seguridad", 0: "Normal"}).value_counts().reset_index()
            seg_df.columns = ["tipo", "count"]
            fig = px.pie(seg_df, names="tipo", values="count",
                         color="tipo",
                         color_discrete_map={"Seguridad": "#EF553B", "Normal": "#00CC96"})
            st.plotly_chart(fig, use_container_width=True)


# ══════════════════════════════════════════════════════════════════════════════
# VISTA: SYSTEM LOGS
# ══════════════════════════════════════════════════════════════════════════════
elif view == "System Logs":
    st.title("🖥️ System Logs")
    st.sidebar.divider()
    df = sidebar_filters(df_sys, "sys")

    # KPIs
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total registros", f"{len(df):,}")
    c2.metric("IPs únicas", df["sourceip"].nunique() if "sourceip" in df.columns else "—")
    sec = int(df["is_security_event"].sum()) if "is_security_event" in df.columns else 0
    c3.metric("Eventos de seguridad", f"{sec:,}", delta_color="inverse")
    if "timestamp" in df.columns and not df.empty:
        span = (df["timestamp"].max() - df["timestamp"].min())
        c4.metric("Ventana de tiempo", str(span).split(".")[0])

    st.divider()

    # ── Volumen total ──────────────────────────────────────────────────────────
    st.subheader("📈 Volumen de logs a lo largo del tiempo")
    if not df.empty and "timestamp" in df.columns:
        gran_sys = st.select_slider(
            "Granularidad", options=["5min", "10min", "30min", "1h"],
            value="10min", key="gran_sys",
        )
        df_vol = df.copy()
        df_vol["bucket"] = df_vol["timestamp"].dt.floor(gran_sys)
        vol_total = df_vol.groupby("bucket").size().reset_index(name="count")
        vol_type  = df_vol.groupby(["bucket", "logtype"]).size().reset_index(name="count")

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=vol_total["bucket"], y=vol_total["count"],
            fill="tozeroy", mode="lines",
            line=dict(color="#1f77b4", width=1.5),
            fillcolor="rgba(31,119,180,0.15)",
            name="Total",
        ))
        for lt, grp in vol_type.groupby("logtype"):
            fig.add_trace(go.Scatter(
                x=grp["bucket"], y=grp["count"],
                mode="lines", name=lt, line=dict(width=1.5),
            ))
        fig.update_layout(
            xaxis_title="Tiempo", yaxis_title="Nº de logs",
            legend=dict(orientation="h", y=1.05),
            hovermode="x unified", height=300,
            margin=dict(t=10, b=40),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.divider()
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Logs por tipo a lo largo del tiempo")
        if not df.empty and "timestamp" in df.columns:
            ts = df.copy()
            ts["hour"] = ts["timestamp"].dt.floor("h")
            agg = ts.groupby(["hour", "logtype"]).size().reset_index(name="count")
            fig = px.line(agg, x="hour", y="count", color="logtype",
                          color_discrete_sequence=px.colors.qualitative.Safe)
            fig.update_layout(xaxis_title="", yaxis_title="Registros/hora", legend_title="Tipo")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("HTTP Status Codes")
        if "http_status_code" in df.columns:
            status_counts = df["http_status_code"].dropna().astype(int).value_counts().reset_index()
            status_counts.columns = ["status_code", "count"]
            status_counts = status_counts.sort_values("status_code")
            fig = px.bar(status_counts, x="status_code", y="count",
                         color="status_code", color_continuous_scale="RdYlGn_r")
            fig.update_layout(xaxis_title="HTTP Status", yaxis_title="Registros", coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)

    col3, col4 = st.columns(2)

    with col3:
        st.subheader("Top 10 IPs por actividad")
        if "sourceip" in df.columns:
            top_ips = df["sourceip"].value_counts().head(10).reset_index()
            top_ips.columns = ["ip", "count"]
            fig = px.bar(top_ips, x="count", y="ip", orientation="h",
                         color="count", color_continuous_scale="Reds")
            fig.update_layout(yaxis=dict(autorange="reversed"), coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)

    with col4:
        st.subheader("Actividad por entorno (sap_app_env)")
        if "sap_app_env" in df.columns:
            env_counts = df["sap_app_env"].value_counts().reset_index()
            env_counts.columns = ["env", "count"]
            fig = px.pie(env_counts, names="env", values="count",
                         color_discrete_sequence=px.colors.qualitative.Set2)
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Datos crudos — System Logs")
    st.dataframe(
        df.sort_values("timestamp", ascending=False).reset_index(drop=True),
        use_container_width=True, height=400,
    )


# ══════════════════════════════════════════════════════════════════════════════
# VISTA: LLM LOGS
# ══════════════════════════════════════════════════════════════════════════════
elif view == "LLM Logs":
    st.title("🤖 LLM Logs")
    st.sidebar.divider()
    df = sidebar_filters(df_llm, "llm")

    # KPIs
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total peticiones", f"{len(df):,}")
    avg_time = df["llm_response_time_ms"].mean() if "llm_response_time_ms" in df.columns else None
    c2.metric("Latencia promedio (ms)", f"{avg_time:,.1f}" if avg_time else "—")
    total_cost = df["llm_cost_usd"].sum() if "llm_cost_usd" in df.columns else 0
    c3.metric("Costo total (USD)", f"${total_cost:,.4f}")
    total_tokens = int(df["llm_total_tokens"].sum()) if "llm_total_tokens" in df.columns else 0
    c4.metric("Tokens consumidos", f"{total_tokens:,}")

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Peticiones LLM por tipo a lo largo del tiempo")
        if not df.empty and "timestamp" in df.columns:
            ts = df.copy()
            ts["hour"] = ts["timestamp"].dt.floor("h")
            agg = ts.groupby(["hour", "logtype"]).size().reset_index(name="count")
            fig = px.line(agg, x="hour", y="count", color="logtype",
                          color_discrete_sequence=px.colors.qualitative.Pastel)
            fig.update_layout(xaxis_title="", yaxis_title="Peticiones/hora")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Distribución de modelos LLM")
        if "llm_model_id" in df.columns:
            model_counts = df["llm_model_id"].value_counts().reset_index()
            model_counts.columns = ["model", "count"]
            fig = px.pie(model_counts, names="model", values="count",
                         color_discrete_sequence=px.colors.qualitative.Bold)
            st.plotly_chart(fig, use_container_width=True)

    # ── Volumen total LLM ──────────────────────────────────────────────────────
    st.subheader("📈 Volumen de peticiones LLM a lo largo del tiempo")
    if not df.empty and "timestamp" in df.columns:
        gran_llm = st.select_slider(
            "Granularidad", options=["5min", "10min", "30min", "1h"],
            value="10min", key="gran_llm",
        )
        df_vol = df.copy()
        df_vol["bucket"] = df_vol["timestamp"].dt.floor(gran_llm)
        vol_total = df_vol.groupby("bucket").size().reset_index(name="count")
        vol_type  = df_vol.groupby(["bucket", "logtype"]).size().reset_index(name="count")

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=vol_total["bucket"], y=vol_total["count"],
            fill="tozeroy", mode="lines",
            line=dict(color="#00CC96", width=1.5),
            fillcolor="rgba(0,204,150,0.15)",
            name="Total",
        ))
        for lt, grp in vol_type.groupby("logtype"):
            fig.add_trace(go.Scatter(
                x=grp["bucket"], y=grp["count"],
                mode="lines", name=lt, line=dict(width=1.5),
            ))
        fig.update_layout(
            xaxis_title="Tiempo", yaxis_title="Nº de peticiones",
            legend=dict(orientation="h", y=1.05),
            hovermode="x unified", height=300,
            margin=dict(t=10, b=40),
        )
        st.plotly_chart(fig, use_container_width=True)

    st.divider()
    col3, col4 = st.columns(2)

    with col3:
        st.subheader("Latencia por modelo (ms)")
        if "llm_model_id" in df.columns and "llm_response_time_ms" in df.columns:
            fig = px.box(df.dropna(subset=["llm_model_id", "llm_response_time_ms"]),
                         x="llm_model_id", y="llm_response_time_ms",
                         color="llm_model_id",
                         color_discrete_sequence=px.colors.qualitative.Vivid)
            fig.update_layout(showlegend=False, xaxis_title="Modelo", yaxis_title="ms")
            st.plotly_chart(fig, use_container_width=True)

    with col4:
        st.subheader("Costo acumulado por región")
        if "macro_region" in df.columns and "llm_cost_usd" in df.columns:
            cost_region = df.groupby("macro_region")["llm_cost_usd"].sum().reset_index()
            cost_region.columns = ["region", "cost_usd"]
            cost_region = cost_region.sort_values("cost_usd", ascending=False)
            fig = px.bar(cost_region, x="region", y="cost_usd",
                         color="cost_usd", color_continuous_scale="Oranges")
            fig.update_layout(xaxis_title="", yaxis_title="USD", coloraxis_showscale=False)
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Datos crudos — LLM Logs")
    cols_show = [c for c in df.columns if c != "llm_prompt"]
    st.dataframe(
        df[cols_show].sort_values("timestamp", ascending=False).reset_index(drop=True),
        use_container_width=True, height=400,
    )
    with st.expander("Ver llm_prompt de registros seleccionados"):
        sample = df[["timestamp", "llm_model_id", "llm_prompt"]].dropna(subset=["llm_prompt"])
        st.dataframe(sample.head(50), use_container_width=True)
