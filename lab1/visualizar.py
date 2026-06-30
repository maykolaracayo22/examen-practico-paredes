import json
import re
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

PATRON_LOG = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) - - \[(.+?)\] "\S+ \S+ \S+" (\d+)'
)

def grafica_top10_ssh():
    with open("reporte_ssh.json") as f:
        data = json.load(f)

    top10 = data["top10_ips"]
    ips = [x["ip"] for x in top10]
    intentos = [x["intentos"] for x in top10]

    fig, ax = plt.subplots(figsize=(12, 6))
    bars = ax.barh(ips[::-1], intentos[::-1], color="crimson")
    ax.set_xlabel("Número de intentos fallidos")
    ax.set_title("Top 10 IPs con más intentos SSH fallidos")
    ax.bar_label(bars, padding=3)
    plt.tight_layout()
    plt.savefig("graficas/top10_ssh.png", dpi=150)
    plt.close()
    print("[+] Guardada: graficas/top10_ssh.png")

def grafica_timeline_http():
    with open("reporte_web.json") as f:
        data = json.load(f)

    horas = sorted(data["peticiones_por_hora"].keys())
    conteos = [data["peticiones_por_hora"][h] for h in horas]

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(horas, conteos, marker="o", color="steelblue", linewidth=2)
    ax.fill_between(horas, conteos, alpha=0.2, color="steelblue")
    ax.set_xlabel("Hora del día")
    ax.set_ylabel("Número de peticiones")
    ax.set_title("Línea de tiempo de peticiones HTTP por hora")
    ax.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.savefig("graficas/timeline_http.png", dpi=150)
    plt.close()
    print("[+] Guardada: graficas/timeline_http.png")

def grafica_heatmap():
    # Leer directamente del access.log para obtener hora y código real
    codigos_interes = [200, 304, 400, 404, 500]
    # hora (0-23) x codigo
    matriz = defaultdict(lambda: defaultdict(int))

    with open("access.log", "r") as f:
        for linea in f:
            m = PATRON_LOG.search(linea)
            if not m:
                continue
            fecha_str = m.group(2)   # ej: 14/Jun/2024:03:13:44 +0000
            codigo = int(m.group(3))
            # Extraer hora: "14/Jun/2024:03:13:44" → hora = "03" → 3
            try:
                hora = int(fecha_str.split(":")[1])
            except:
                continue
            if codigo in codigos_interes:
                matriz[hora][codigo] += 1

    # Construir la matriz numpy ordenada
    horas = list(range(24))
    datos = np.zeros((len(codigos_interes), 24), dtype=int)
    for h in horas:
        for j, cod in enumerate(codigos_interes):
            datos[j][h] = matriz[h][cod]

    fig, ax = plt.subplots(figsize=(16, 5))
    im = ax.imshow(datos, aspect="auto", cmap="YlOrRd", interpolation="nearest")
    ax.set_xticks(range(24))
    ax.set_xticklabels([str(h).zfill(2) for h in range(24)])
    ax.set_yticks(range(len(codigos_interes)))
    ax.set_yticklabels([str(c) for c in codigos_interes])
    ax.set_xlabel("Hora del día")
    ax.set_ylabel("Código HTTP")
    ax.set_title("Heatmap de peticiones por hora y código HTTP")

    # Añadir valores en cada celda
    for i in range(len(codigos_interes)):
        for j in range(24):
            val = datos[i][j]
            if val > 0:
                ax.text(j, i, str(val), ha="center", va="center",
                        fontsize=7, color="black")

    plt.colorbar(im, ax=ax, label="Número de peticiones")
    plt.tight_layout()
    plt.savefig("graficas/heatmap_http.png", dpi=150)
    plt.close()
    print("[+] Guardada: graficas/heatmap_http.png")

if __name__ == "__main__":
    grafica_top10_ssh()
    grafica_timeline_http()
    grafica_heatmap()
    print("[+] Todas las gráficas generadas en graficas/")
