#!/usr/bin/env python3
"""
Script de simulación de ataque SSH Brute Force
para generar alertas en Wazuh - Lab 2
"""
import subprocess
import time
import datetime

OBJETIVO = "127.0.0.1"
USUARIO = "root"
INTENTOS = 20

print(f"[*] Iniciando simulación de Brute Force SSH")
print(f"[*] Objetivo : {OBJETIVO}")
print(f"[*] Usuario  : {USUARIO}")
print(f"[*] Intentos : {INTENTOS}")
print(f"[*] Hora     : {datetime.datetime.now()}")
print("-" * 50)

for i in range(1, INTENTOS + 1):
    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "ConnectTimeout=2",
         "-o", "PasswordAuthentication=yes",
         f"{USUARIO}@{OBJETIVO}"],
        capture_output=True, text=True
    )
    print(f"[{i:02d}/{INTENTOS}] Intento enviado -> {OBJETIVO}")
    time.sleep(0.5)

print("-" * 50)
print(f"[+] Simulación completada: {INTENTOS} intentos enviados")
print(f"[+] Revisa las alertas en: /var/ossec/logs/alerts/alerts.log")
