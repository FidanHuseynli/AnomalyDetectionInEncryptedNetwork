#!/usr/bin/env python3
import argparse
import csv
import json
import time
from collections import deque
from pathlib import Path

import numpy as np
from nfstream import NFStreamer
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Şifreli trafikte de görünen, IP/port gibi "sızıntı" yaratmayan sayısal özellikler
NUMERIC_FEATURES = [
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_max_ps",
    "bidirectional_min_ps",
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_max_piat_ms",
    "bidirectional_syn_packets",
    "bidirectional_fin_packets",
    "bidirectional_rst_packets",
]

# Raporlama için tutulan kimlik / TLS metadata alanları (modele girmez)
META_FIELDS = [
    "id", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "application_name", "application_category_name",
    "requested_server_name", "client_fingerprint", "server_fingerprint",
]

SPLT_FIELDS = ["splt_direction", "splt_ps", "splt_piat_ms"]


def flow_to_row(flow) -> dict:
    """NFlow nesnesini düz bir sözlüğe çevirir."""
    row = {k: getattr(flow, k, None) for k in META_FIELDS}
    for k in NUMERIC_FEATURES:
        row[k] = getattr(flow, k, 0) or 0
    for k in SPLT_FIELDS:
        v = getattr(flow, k, None)
        row[k] = json.dumps(list(v)) if v is not None else "[]"
    row["timestamp"] = time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(flow.bidirectional_first_seen_ms / 1000),
    )
    return row


def feature_vector(row: dict) -> list:
    return [float(row[k]) for k in NUMERIC_FEATURES]


class AnomalyScorer:
    """İlk `warmup` akışla baseline öğrenir, sonra her akışa skor verir."""

    def __init__(self, warmup: int, contamination: float, retrain_every: int):
        self.warmup = warmup
        self.contamination = contamination
        self.retrain_every = retrain_every
        self.buffer = deque(maxlen=20000)  # baseline havuzu
        self.model = None
        self.scaler = None
        self.seen = 0

    def _fit(self):
        X = np.log1p(np.array(self.buffer, dtype=float).clip(min=0))
        self.scaler = StandardScaler().fit(X)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        ).fit(self.scaler.transform(X))

    def score(self, vec: list):
        """(skor, anomali_mi) döndürür. Baseline hazır değilse (None, False)."""
        self.seen += 1

        if self.model is None:
            self.buffer.append(vec)
            if len(self.buffer) >= self.warmup:
                self._fit()
                print(f"[+] Baseline modeli eğitildi ({len(self.buffer)} akış).")
            return None, False

        x = np.log1p(np.array([vec], dtype=float).clip(min=0))
        x = self.scaler.transform(x)
        raw = self.model.decision_function(x)[0]   # düşük = daha anormal
        is_anom = self.model.predict(x)[0] == -1

        # Anormal olmayan akışları baseline'a ekle, periyodik yeniden eğit
        if not is_anom:
            self.buffer.append(vec)
        if self.seen % self.retrain_every == 0:
            self._fit()
        return float(-raw), bool(is_anom)  # yüksek skor = daha şüpheli


def main():
    p = argparse.ArgumentParser(description="Şifreli trafik akış izleyici")
    p.add_argument("--source", required=True, help="Arayüz adı (eth0) veya .pcap yolu")
    p.add_argument("--out", default="flows.csv", help="Çıktı CSV dosyası")
    p.add_argument("--alerts", default="alerts.jsonl", help="Uyarı log dosyası")
    p.add_argument("--warmup", type=int, default=2000, help="Baseline için akış sayısı")
    p.add_argument("--contamination", type=float, default=0.01)
    p.add_argument("--retrain-every", type=int, default=5000)
    p.add_argument("--idle-timeout", type=int, default=30)
    p.add_argument("--active-timeout", type=int, default=120)
    args = p.parse_args()

    streamer = NFStreamer(
        source=args.source,
        statistical_analysis=True,   # paket boyutu / PIAT istatistikleri
        splt_analysis=20,            # ilk 20 paketin yön/boyut/zaman dizisi
        n_dissections=20,            # nDPI: TLS SNI, JA3 vb. (gerekli)
        idle_timeout=args.idle_timeout,
        active_timeout=args.active_timeout,
    )

    scorer = AnomalyScorer(args.warmup, args.contamination, args.retrain_every)
    fieldnames = META_FIELDS + NUMERIC_FEATURES + SPLT_FIELDS + [
        "timestamp", "anomaly_score", "is_anomaly",
    ]

    new_file = not Path(args.out).exists()
    print(f"[*] Dinleniyor: {args.source}  (durdurmak için Ctrl+C)")

    try:
        with open(args.out, "a", newline="", encoding="utf-8") as f_csv, \
             open(args.alerts, "a", encoding="utf-8") as f_alert:

            writer = csv.DictWriter(f_csv, fieldnames=fieldnames)
            if new_file:
                writer.writeheader()

            for flow in streamer:
                row = flow_to_row(flow)
                score, is_anom = scorer.score(feature_vector(row))
                row["anomaly_score"] = round(score, 4) if score is not None else ""
                row["is_anomaly"] = int(is_anom)
                writer.writerow(row)
                f_csv.flush()

                if is_anom:
                    alert = {k: row[k] for k in META_FIELDS + ["timestamp", "anomaly_score"]}
                    alert["packets"] = row["bidirectional_packets"]
                    alert["bytes"] = row["bidirectional_bytes"]
                    f_alert.write(json.dumps(alert, ensure_ascii=False) + "\n")
                    f_alert.flush()
                    print(
                        f"[!] ANOMALİ skor={score:.3f} "
                        f"{row['src_ip']}:{row['src_port']} -> "
                        f"{row['dst_ip']}:{row['dst_port']} "
                        f"SNI={row['requested_server_name'] or '-'} "
                        f"JA3={row['client_fingerprint'] or '-'}"
                    )
    except KeyboardInterrupt:
        print("\n[*] Durduruldu.")

    print(f"[*] Akışlar: {args.out} | Uyarılar: {args.alerts}")


if __name__ == "__main__":
    main()