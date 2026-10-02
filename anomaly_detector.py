"""
Log-Anomaly-Detector-ML
Sunucu ve Ag Loglarinda Makine Ogrenmesi (Isolation Forest) ile Anomali ve Brute-Force Tespiti.
"""

import sys
import os

# Windows konsol UTF-8 uyumlulugu
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

def generate_mock_log_features(n_normal=500, n_anomalies=25):
    """
    Simule edilmis ag/sunucu IP davranis veri seti olusturur.
    Oznitelikler (Features):
      - req_per_min: Dakika basina istek sayisi
      - failed_logins: Basarisiz giris denemesi sayisi
      - unique_endpoints: Ziyaret edilen farkli sayfa sayisi
      - error_4xx_count: 401/403/404 donen hata sayisi
    """
    np.random.seed(42)

    # Normal kullanici trafigi
    normal_req = np.random.normal(loc=15, scale=5, size=n_normal).clip(1, 40)
    normal_failed = np.random.poisson(lam=0.2, size=n_normal)
    normal_endpoints = np.random.normal(loc=8, scale=3, size=n_normal).clip(1, 20)
    normal_errors = np.random.poisson(lam=0.5, size=n_normal)

    normal_df = pd.DataFrame({
        "ip_address": [f"192.168.1.{i%250 + 1}" for i in range(n_normal)],
        "req_per_min": normal_req,
        "failed_logins": normal_failed,
        "unique_endpoints": normal_endpoints,
        "error_4xx_count": normal_errors,
        "true_label": "Normal"
    })

    # Anomali / Saldiri trafigi (Brute Force, DDoS, Scanner)
    anomaly_req = np.random.normal(loc=180, scale=40, size=n_anomalies).clip(50, 400)
    anomaly_failed = np.random.normal(loc=35, scale=10, size=n_anomalies).clip(10, 80)
    anomaly_endpoints = np.random.normal(loc=45, scale=10, size=n_anomalies).clip(20, 100)
    anomaly_errors = np.random.normal(loc=50, scale=15, size=n_anomalies).clip(15, 120)

    anomaly_df = pd.DataFrame({
        "ip_address": [f"10.0.0.{i+1}" for i in range(n_anomalies)],
        "req_per_min": anomaly_req,
        "failed_logins": anomaly_failed,
        "unique_endpoints": anomaly_endpoints,
        "error_4xx_count": anomaly_errors,
        "true_label": "Attack / Anomaly"
    })

    full_df = pd.concat([normal_df, anomaly_df]).sample(frac=1, random_state=42).reset_index(drop=True)
    return full_df

class SecurityLogAnomalyDetector:
    def __init__(self, contamination=0.04):
        self.model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        self.feature_cols = ["req_per_min", "failed_logins", "unique_endpoints", "error_4xx_count"]

    def fit_and_detect(self, df: pd.DataFrame):
        X = df[self.feature_cols]
        # Isolation Forest: -1 -> Anomali, 1 -> Normal
        predictions = self.model.fit_predict(X)
        scores = self.model.decision_function(X)

        df["anomaly_prediction"] = np.where(predictions == -1, "[!] ANOMALI / TEHDIT", "[+] NORMAL")
        df["anomaly_score"] = scores
        return df

if __name__ == "__main__":
    print("=" * 70)
    print("[*] SIEM / Ag Trafigi Icin Makine Ogrenmesi ile Anomali Tespiti")
    print("=" * 70)

    print("\n[+] Sunucu log akisi simule ediliyor...")
    logs_df = generate_mock_log_features(n_normal=600, n_anomalies=20)
    print(f"[*] Toplam incelenen IP oturumu: {len(logs_df)}")

    detector = SecurityLogAnomalyDetector(contamination=0.035)
    analyzed_df = detector.fit_and_detect(logs_df)

    flagged_threats = analyzed_df[analyzed_df["anomaly_prediction"] == "[!] ANOMALI / TEHDIT"]

    print(f"\n[!] Tespit Edilen Supheli IP Sayisi: {len(flagged_threats)}")
    print("\n=== Ilk 5 Tespit Edilen Supheli Aktivite ===")
    preview_cols = ["ip_address", "req_per_min", "failed_logins", "error_4xx_count", "true_label"]
    print(flagged_threats[preview_cols].head().to_string(index=False))

    # Anomali Raporu CSV olarak disari aktariliyor
    report_file = os.path.join(os.path.dirname(__file__), "anomaly_report.csv")
    flagged_threats.to_csv(report_file, index=False)
    print(f"\n[+] Detayli guvenlik raporu kaydedildi: {report_file}")
    print("[+] Analiz basariyla tamamlandi.")
