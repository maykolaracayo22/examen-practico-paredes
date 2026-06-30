import re
import json
from collections import defaultdict

LOG_FILE = "auth.log"
OUTPUT_FILE = "reporte_ssh.json"
UMBRAL_ALERTA = 50

def analizar_ssh(log_file):
    intentos_por_ip = defaultdict(int)
    usuarios_por_ip = defaultdict(set)
    patron = re.compile(
        r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'
    )

    with open(log_file, "r") as f:
        for linea in f:
            match = patron.search(linea)
            if match:
                usuario, ip = match.group(1), match.group(2)
                intentos_por_ip[ip] += 1
                usuarios_por_ip[ip].add(usuario)

    # Ordenar por mayor cantidad de intentos
    ranking = sorted(intentos_por_ip.items(), key=lambda x: x[1], reverse=True)
    top10 = ranking[:10]

    alertas = []
    for ip, intentos in intentos_por_ip.items():
        if intentos >= UMBRAL_ALERTA:
            alertas.append({"ip": ip, "intentos": intentos})

    reporte = {
        "resumen": {
            "total_ips_atacantes": len(intentos_por_ip),
            "total_intentos_fallidos": sum(intentos_por_ip.values()),
            "umbral_alerta": UMBRAL_ALERTA
        },
        "top10_ips": [
            {
                "ip": ip,
                "intentos": intentos,
                "usuarios_probados": list(usuarios_por_ip[ip])
            }
            for ip, intentos in top10
        ],
        "alertas": alertas
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(reporte, f, indent=4)

    print(f"[+] Análisis SSH completado.")
    print(f"    Total IPs atacantes : {reporte['resumen']['total_ips_atacantes']}")
    print(f"    Total intentos      : {reporte['resumen']['total_intentos_fallidos']}")
    print(f"    Alertas (>={UMBRAL_ALERTA}): {len(alertas)}")
    print(f"[+] Reporte guardado en: {OUTPUT_FILE}")

    return reporte

if __name__ == "__main__":
    analizar_ssh(LOG_FILE)
