import re
import json
from collections import defaultdict

LOG_FILE = "access.log"
OUTPUT_FILE = "reporte_web.json"

PATRON_SQLI = re.compile(
    r"(union.*select|select.*from|insert.*into|drop.*table|'|--|;--|/\*|\*/|xp_|exec\(|CAST\()",
    re.IGNORECASE
)

RUTAS_ESCANEO = [
    "/admin", "/phpmyadmin", "/.env", "/wp-admin", "/backup",
    "/config", "/.git", "/etc/passwd", "/server-status"
]

PATRON_LOG = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) - - \[(.+?)\] "(\S+) (\S+) \S+" (\d+) (\d+) ".*?" "(.*?)"'
)

def analizar_web(log_file):
    codigos_por_ip = defaultdict(lambda: defaultdict(int))
    escaneo_por_ip = defaultdict(set)
    sqli_por_ip = defaultdict(list)
    peticiones_por_hora = defaultdict(int)

    with open(log_file, "r") as f:
        for linea in f:
            m = PATRON_LOG.search(linea)
            if not m:
                continue
            ip, fecha, metodo, ruta, codigo, _, agente = m.groups()
            codigo = int(codigo)

            # Conteo de códigos por IP
            codigos_por_ip[ip][codigo] += 1

            # Hora para timeline
            hora = fecha.split(":")[1]
            peticiones_por_hora[hora] += 1

            # Detección de escaneo de directorios
            for ruta_sospechosa in RUTAS_ESCANEO:
                if ruta_sospechosa in ruta:
                    escaneo_por_ip[ip].add(ruta)

            # Detección de SQL Injection
            if PATRON_SQLI.search(ruta):
                sqli_por_ip[ip].append(ruta)

    # IPs con más errores 4xx/5xx
    ips_errores = []
    for ip, codigos in codigos_por_ip.items():
        errores = sum(v for k, v in codigos.items() if k >= 400)
        if errores > 0:
            ips_errores.append({"ip": ip, "errores": errores, "detalle": dict(codigos)})
    ips_errores.sort(key=lambda x: x["errores"], reverse=True)

    reporte = {
        "resumen": {
            "total_ips": len(codigos_por_ip),
            "ips_con_escaneo": len(escaneo_por_ip),
            "ips_con_sqli": len(sqli_por_ip)
        },
        "top_ips_errores": ips_errores[:10],
        "escaneo_directorios": {ip: list(rutas) for ip, rutas in escaneo_por_ip.items()},
        "intentos_sqli": {ip: rutas for ip, rutas in sqli_por_ip.items()},
        "peticiones_por_hora": dict(sorted(peticiones_por_hora.items()))
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(reporte, f, indent=4)

    print(f"[+] Análisis WEB completado.")
    print(f"    IPs únicas          : {reporte['resumen']['total_ips']}")
    print(f"    IPs con escaneo     : {reporte['resumen']['ips_con_escaneo']}")
    print(f"    IPs con SQLi        : {reporte['resumen']['ips_con_sqli']}")
    print(f"[+] Reporte guardado en: {OUTPUT_FILE}")

    return reporte

if __name__ == "__main__":
    analizar_web(LOG_FILE)
