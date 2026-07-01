#!/usr/bin/env python3
"""
Parsea /var/ossec/logs/alerts/alerts.log y genera
una base de datos SQLite para Grafana
"""
import re
import sqlite3
import os
from datetime import datetime

ALERTS_LOG = os.path.expanduser("~/examen-practico-paredes/lab4/alerts.log")
DB_PATH    = os.path.expanduser("~/examen-practico-paredes/lab4/wazuh_alerts.db")

PATRON_ALERT = re.compile(
    r'\*\* Alert (\d+\.\d+).*?\n'
    r'(\d{4} \w+ \d+ \d+:\d+:\d+) (\S+)->(\S+)\n'
    r'Rule: (\d+) \(level (\d+)\) -> \'(.+?)\''
    , re.DOTALL
)

def crear_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            source TEXT,
            rule_id INTEGER,
            level INTEGER,
            description TEXT,
            hora INTEGER
        )
    """)
    conn.commit()

def parsear_e_insertar(conn):
    with open(ALERTS_LOG, "r", errors="ignore") as f:
        contenido = f.read()

    bloques = contenido.split("** Alert ")
    insertados = 0

    for bloque in bloques[1:]:
        lineas = bloque.strip().split("\n")
        if len(lineas) < 3:
            continue
        try:
            # Fecha
            fecha_str = lineas[1].strip()
            partes    = fecha_str.split(" ")
            timestamp = " ".join(partes[:4]) if len(partes) >= 4 else fecha_str

            # Host y fuente
            host_src = partes[4] if len(partes) > 4 else "unknown"
            if "->" in host_src:
                hostname, source = host_src.split("->", 1)
            else:
                hostname, source = host_src, "unknown"

            # Regla
            rule_match = re.search(r'Rule: (\d+) \(level (\d+)\) -> \'(.+?)\'', bloque)
            if not rule_match:
                continue

            rule_id     = int(rule_match.group(1))
            level       = int(rule_match.group(2))
            description = rule_match.group(3)

            # Hora
            hora_match = re.search(r'\d{4} \w+ \d+ (\d+):', timestamp)
            hora = int(hora_match.group(1)) if hora_match else 0

            conn.execute("""
                INSERT INTO alerts (timestamp, hostname, source, rule_id, level, description, hora)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, hostname, source, rule_id, level, description, hora))
            insertados += 1
        except Exception:
            continue

    conn.commit()
    return insertados

def main():
    conn = sqlite3.connect(DB_PATH)
    crear_db(conn)
    n = parsear_e_insertar(conn)
    print(f"[+] Alertas insertadas en SQLite: {n}")
    print(f"[+] Base de datos: {DB_PATH}")

    # Resumen
    cur = conn.execute("SELECT level, COUNT(*) FROM alerts GROUP BY level ORDER BY level DESC")
    print("\n  Nivel | Cantidad")
    print("  ------|----------")
    for row in cur:
        print(f"    {row[0]:3}  | {row[1]}")

    conn.close()

if __name__ == "__main__":
    main()
