# Anomaly Detection in Encrypted Network Traffic

Graduation thesis project. Most internet traffic is encrypted, so payload inspection is no longer an option. This project detects suspicious connections using only the metadata that stays visible in encrypted traffic (flow statistics, packet size and timing patterns, TLS/QUIC handshake fields), and is designed to add an **LLM agent** that investigates and explains the alerts like a SOC analyst.

## Idea

```
PCAP / live traffic
      |
Feature extraction (NFStream)
      |
Anomaly detector (Isolation Forest)
      |  (only high-scoring flows)
LLM agent (planned): investigates the alert with tools
      |
Report: verdict + confidence + evidence + recommended action
```

A classical ML model is fast and cheap enough to score every flow, but it only says "this is unusual", not "this is dangerous". An LLM is too slow and expensive for millions of flows, but good at reasoning over context. The hybrid design uses each where it is strongest.

## Current status

| Component | Status |
|---|---|
| Flow extraction and TLS/QUIC metadata (SNI, fingerprints) | Done |
| Baseline learning and anomaly scoring (Isolation Forest) | Done |
| Streamlit dashboard | Done |
| LLM agent for alert triage | Planned |
| Evaluation on labeled datasets (CIC-IDS2018 etc.) | Planned |

## How it works

1. **Capture.** Traffic is read from a live interface or a `.pcap`/`.pcapng` file.
2. **Flow extraction.** [NFStream](https://www.nfstream.org/) groups packets into bidirectional flows and computes duration, packet and byte counts, packet size and inter-arrival time statistics, TCP flag counts, and the size/direction/timing sequence of the first 20 packets. Its nDPI dissector also extracts the TLS/QUIC server name (SNI) and the client fingerprint (JA4-style).
3. **Baseline.** The first `--warmup` flows are treated as normal traffic. Features are log-scaled and standardized, then an Isolation Forest is trained on them.
4. **Scoring.** Every following flow gets an anomaly score (higher means more suspicious). Flows flagged as anomalies are written to `alerts.jsonl`. Normal flows are added to the baseline and the model is retrained periodically.
5. **Dashboard.** A Streamlit app visualizes flows, score distribution, top domains and the alert table.

IP addresses and ports are deliberately **not** fed to the model, to avoid label leakage and to rely only on behavior that is observable in encrypted traffic.

## Installation

Requires Python 3.11+ (tested on 3.14 / Windows).

```bash
pip install nfstream pandas scikit-learn numpy streamlit
```

- **Windows:** install [Npcap](https://npcap.com/) with "WinPcap API-compatible Mode" enabled. Live capture needs an administrator shell and interface names in the `\Device\NPF_{GUID}` form (find the GUID with `Get-NetAdapter | Select Name, InterfaceGuid`).
- **Linux:** install `libpcap-dev`. Live capture needs root.

## Usage

Analyze a PCAP file (recommended for a first run):

```bash
python monitorTraffic.py --source example.pcapng --warmup 200
```

Live capture:

```bash
python monitorTraffic.py --source "\Device\NPF_{GUID}" --warmup 2000
```

Open the dashboard:

```bash
python -m streamlit run dashboard.py
```

### Options

| Option | Default | Description |
|---|---|---|
| `--source` | required | Interface name or path to a PCAP file |
| `--out` | `flows.csv` | Output CSV with all flows |
| `--alerts` | `alerts.jsonl` | Log of flagged anomalies |
| `--warmup` | 2000 | Number of flows used to learn the baseline |
| `--contamination` | 0.01 | Expected share of anomalies |
| `--retrain-every` | 5000 | Retrain the model every N flows |
| `--idle-timeout` / `--active-timeout` | 30 / 120 | Flow expiration timers (seconds) |

Note: output files are appended on every run. Delete `flows.csv` and `alerts.jsonl` before a fresh run.

## Limitations

- The detector is unsupervised: it flags **rare** flows, not necessarily **malicious** ones. Large downloads and unusual-but-benign traffic can be flagged, which is exactly what the LLM triage stage is meant to address.
- The baseline assumes the warmup period is clean. If attack traffic is present during warmup, it will be learned as normal.
- Results on self-captured traffic cannot be measured without ground-truth labels, so quantitative evaluation requires a labeled dataset.

## Roadmap

- [ ] LLM agent with tools: flow details lookup, baseline comparison, fingerprint and domain/IP enrichment, similar-incident search
- [ ] Structured agent output: `{verdict, confidence, evidence, recommended_action}`
- [ ] Defenses against prompt injection from attacker-controlled fields (SNI, certificate data)
- [ ] Evaluation on CIC-IDS2018 and other labeled datasets (precision, recall, F1, PR-AUC, false positive rate)
- [ ] Ablation study: ML only vs. LLM only vs. ML + agent, and per-tool contribution
- [ ] Alert triage button in the dashboard

## Privacy

Captured traffic contains IP addresses and the domains visited. Do not commit real captures or generated CSV/JSONL files to a public repository. The `.gitignore` excludes `flows.csv`, `alerts.jsonl` and PCAP files. Only monitor networks you own or are authorized to analyze.

## Project structure

```
monitorTraffic.py   # capture, feature extraction, anomaly scoring
dashboard.py        # Streamlit dashboard
README.md
.gitignore
```
