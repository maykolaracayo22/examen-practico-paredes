import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

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
    with open("reporte_web.json") as f:
        data = json.load(f)

    horas = [str(h).zfill(2) for h in range(24)]
    codigos = [200, 304, 400, 404, 500]
    matriz = np.zeros((len(codigos), len(horas)), dtype=int)

    # Reconstruir matriz desde top_ips_errores
    for entrada in data["top_ips_errores"]:
        for cod_str, cnt in entrada["detalle"].items():
            cod = int(cod_str)
            if cod in codigos:
                fila = codigos.index(cod)
                # Distribuir uniformemente entre horas (aproximación)
                for h in range(24):
                    matriz[fila][h] += cnt // 24

    fig, ax = plt.subplots(figsize=(16, 5))
    im = ax.imshow(matriz, aspect="auto", cmap="YlOrRd")
    ax.set_xticks(range(24))
    ax.set_xticklabels(horas)
    ax.set_yticks(range(len(codigos)))
    ax.set_yticklabels([str(c) for c in codigos])
    ax.set_xlabel("Hora del día")
    ax.set_ylabel("Código HTTP")
    ax.set_title("Heatmap de peticiones por hora y código HTTP")
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
