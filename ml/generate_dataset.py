"""
ShieldAI - Synthetic Traffic Dataset Generator
Generates 25,000 labeled network traffic records for classifier training.
"""

import numpy as np
import pandas as pd
from sklearn.utils import shuffle

np.random.seed(42)

N = 25000

def generate_clean(n):
    return pd.DataFrame({
        "request_rate":       np.random.normal(5, 2, n).clip(1, 20),
        "payload_size":       np.random.normal(500, 150, n).clip(50, 1200),
        "unique_endpoints":   np.random.randint(1, 6, n),
        "error_rate":         np.random.uniform(0, 0.05, n),
        "has_sql_keywords":   np.zeros(n, dtype=int),
        "header_anomaly":     np.random.choice([0, 1], n, p=[0.97, 0.03]),
        "geo_risk_score":     np.random.uniform(0, 0.2, n),
        "repeated_ip":        np.random.choice([0, 1], n, p=[0.85, 0.15]),
        "label":              ["clean"] * n
    })

def generate_ddos(n):
    return pd.DataFrame({
        "request_rate":       np.random.normal(800, 200, n).clip(200, 2000),
        "payload_size":       np.random.normal(120, 40, n).clip(50, 300),
        "unique_endpoints":   np.random.randint(1, 3, n),
        "error_rate":         np.random.uniform(0.3, 0.9, n),
        "has_sql_keywords":   np.zeros(n, dtype=int),
        "header_anomaly":     np.random.choice([0, 1], n, p=[0.4, 0.6]),
        "geo_risk_score":     np.random.uniform(0.5, 1.0, n),
        "repeated_ip":        np.ones(n, dtype=int),
        "label":              ["ddos"] * n
    })

def generate_sqli(n):
    return pd.DataFrame({
        "request_rate":       np.random.normal(8, 3, n).clip(1, 30),
        "payload_size":       np.random.normal(1800, 400, n).clip(800, 4000),
        "unique_endpoints":   np.random.randint(3, 15, n),
        "error_rate":         np.random.uniform(0.1, 0.5, n),
        "has_sql_keywords":   np.ones(n, dtype=int),
        "header_anomaly":     np.random.choice([0, 1], n, p=[0.6, 0.4]),
        "geo_risk_score":     np.random.uniform(0.3, 0.8, n),
        "repeated_ip":        np.random.choice([0, 1], n, p=[0.5, 0.5]),
        "label":              ["sqli"] * n
    })

def generate_suspicious(n):
    return pd.DataFrame({
        "request_rate":       np.random.normal(40, 15, n).clip(10, 150),
        "payload_size":       np.random.normal(900, 300, n).clip(200, 3000),
        "unique_endpoints":   np.random.randint(5, 20, n),
        "error_rate":         np.random.uniform(0.05, 0.3, n),
        "has_sql_keywords":   np.random.choice([0, 1], n, p=[0.7, 0.3]),
        "header_anomaly":     np.random.choice([0, 1], n, p=[0.5, 0.5]),
        "geo_risk_score":     np.random.uniform(0.2, 0.6, n),
        "repeated_ip":        np.random.choice([0, 1], n, p=[0.4, 0.6]),
        "label":              ["suspicious"] * n
    })

# Class distribution matching real-world proportions
clean      = generate_clean(int(N * 0.72))
ddos       = generate_ddos(int(N * 0.12))
sqli       = generate_sqli(int(N * 0.08))
suspicious = generate_suspicious(int(N * 0.08))

df = shuffle(pd.concat([clean, ddos, sqli, suspicious], ignore_index=True), random_state=42)
df.to_csv("data/traffic_dataset.csv", index=False)

print(f"Dataset saved: {len(df)} records")
print(df["label"].value_counts())
