"""
Encrypted traffic anomaly dashboard (Streamlit)

Install:  py -m pip install streamlit pandas
Run:      py -m streamlit run dashboard.py

Reads the flows.csv file produced by monitorTraffic.py.
You can also upload a different CSV from the sidebar.
"""

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Encrypted Traffic Anomaly Dashboard", layout="wide")
st.title("Anomaly Detection in Encrypted Network Traffic")

# ---------- Data loading ----------
st.sidebar.header("Data")
uploaded = st.sidebar.file_uploader("Upload flows.csv (optional)", type="csv")
path = st.sidebar.text_input("Or file path", "flows.csv")


@st.cache_data
def load(src):
    df = pd.read_csv(src)
    df["is_anomaly"] = df["is_anomaly"].fillna(0).astype(int)
    df["anomaly_score"] = pd.to_numeric(df["anomaly_score"], errors="coerce")
    df["requested_server_name"] = df["requested_server_name"].fillna("")
    return df


try:
    df = load(uploaded if uploaded else path)
except FileNotFoundError:
    st.error(f"'{path}' not found. Generate flows first with monitorTraffic.py.")
    st.stop()

# ---------- Filters ----------
st.sidebar.header("Filters")
only_tls = st.sidebar.checkbox("Only flows with SNI (TLS/QUIC)", False)
only_anom = st.sidebar.checkbox("Only anomalies", False)
min_score = st.sidebar.slider("Minimum anomaly score", 0.0, 0.5, 0.0, 0.005)

view = df.copy()
if only_tls:
    view = view[view["requested_server_name"] != ""]
if only_anom:
    view = view[view["is_anomaly"] == 1]
view = view[(view["anomaly_score"].fillna(0) >= min_score) | (view["is_anomaly"] == 0)]

# ---------- Summary metrics ----------
scored = df["anomaly_score"].notna().sum()
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total flows", len(df))
c2.metric("Flows with SNI", int((df["requested_server_name"] != "").sum()))
c3.metric("Scored flows", int(scored))
c4.metric("Anomalies", int(df["is_anomaly"].sum()))

# ---------- Charts ----------
left, right = st.columns(2)

with left:
    st.subheader("Anomaly score distribution")
    scores = df["anomaly_score"].dropna()
    if len(scores):
        hist = pd.cut(scores, bins=20).value_counts().sort_index()
        hist.index = [f"{i.left:.2f}" for i in hist.index]
        st.bar_chart(hist)
    else:
        st.info("No scored flows yet (the warmup phase may not have finished).")

with right:
    st.subheader("Packets vs. bytes (anomalies highlighted)")
    plot = view.copy()
    plot["type"] = plot["is_anomaly"].map({0: "normal", 1: "anomaly"})
    st.scatter_chart(
        plot,
        x="bidirectional_packets",
        y="bidirectional_bytes",
        color="type",
    )

st.subheader("Top domains by traffic volume (SNI)")
top = (
    view[view["requested_server_name"] != ""]
    .groupby("requested_server_name")["bidirectional_bytes"]
    .sum()
    .sort_values(ascending=False)
    .head(15)
)
st.bar_chart(top)

# ---------- Alerts table ----------
st.subheader("Anomaly alerts")
cols = [
    "timestamp", "src_ip", "dst_ip", "dst_port", "requested_server_name",
    "client_fingerprint", "bidirectional_packets", "bidirectional_bytes",
    "bidirectional_duration_ms", "anomaly_score",
]
alerts = view[view["is_anomaly"] == 1].sort_values("anomaly_score", ascending=False)
st.dataframe(alerts[[c for c in cols if c in alerts.columns]], use_container_width=True)

with st.expander("All flows"):
    st.dataframe(view[[c for c in cols if c in view.columns]], use_container_width=True)