#!/usr/bin/env python3
"""
predecir.py - Clasificador de tráfico de red usando modelo entrenado
Uso: python3 predecir.py <archivo_csv>
"""
import sys
import pickle
import pandas as pd
import numpy as np

MODELO_PATH = "modelo_anomalias.pkl"

def cargar_modelo():
    with open(MODELO_PATH, "rb") as f:
        data = pickle.load(f)
    return data["modelo"], data["scaler"], data["features"], data["umbral"]

def preprocesar(df, features):
    df = df.copy()
    df["protocol_enc"]  = df["protocol"].map({"TCP": 0, "UDP": 1, "ICMP": 2}).fillna(3)
    df["bytes_ratio"]   = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["bytes_per_pkt"] = df["bytes_sent"] / (df["packets"] + 1)
    df["pkts_per_sec"]  = df["packets"]    / (df["duration_sec"] + 1)
    return df[features]

def predecir(csv_path):
    print(f"[*] Cargando modelo desde: {MODELO_PATH}")
    modelo, scaler, features, umbral = cargar_modelo()

    print(f"[*] Leyendo archivo     : {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"[*] Registros a evaluar : {len(df)}")

    X = preprocesar(df, features)
    X_scaled = scaler.transform(X)

    scores   = modelo.decision_function(X_scaled)
    y_pred   = np.where(scores < umbral, "anomalia", "normal")

    df["anomaly_score"] = scores
    df["prediccion"]    = y_pred

    total     = len(df)
    anomalias = (y_pred == "anomalia").sum()
    normales  = (y_pred == "normal").sum()

    print(f"\n{'='*50}")
    print(f"  RESULTADOS DE CLASIFICACIÓN")
    print(f"{'='*50}")
    print(f"  Total registros : {total}")
    print(f"  Normales        : {normales} ({normales/total*100:.1f}%)")
    print(f"  Anomalías       : {anomalias} ({anomalias/total*100:.1f}%)")
    print(f"{'='*50}")

    if anomalias > 0:
        print(f"\n  Top anomalías más severas:")
        top = (df[df["prediccion"] == "anomalia"]
               .sort_values("anomaly_score")
               .head(5)[["src_ip","dst_ip","dst_port","protocol",
                          "bytes_sent","anomaly_score"]])
        print(top.to_string(index=False))

    salida = csv_path.replace(".csv", "_resultado.csv")
    df.to_csv(salida, index=False)
    print(f"\n[+] Resultado guardado en: {salida}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 predecir.py <archivo_csv>")
        sys.exit(1)
    predecir(sys.argv[1])
