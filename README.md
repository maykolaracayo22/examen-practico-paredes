# Examen Práctico Final — Seguridad Informática
## Unidad IV: Monitoreo de Seguridad, SIEM e Inteligencia Artificial

**Alumno:** Maykol Paredes  
**Repositorio:** examen-practico-paredes  
**Fecha:** Junio 2026  

---

## Entorno de Trabajo

| Componente | Detalle |
|---|---|
| Sistema Operativo | Ubuntu Desktop 24.04 LTS |
| Virtualización | VirtualBox (Windows 11 Host) |
| RAM asignada | 8 GB |
| Python | 3.12 |
| Wazuh Manager | 4.x |
| Grafana | OSS (latest) |
| Jupyter Notebook | 7.x |

---

## Estructura del Repositorio

```
examen-practico-paredes/
├── README.md
├── lab1/
│   ├── auth.log
│   ├── access.log
│   ├── analizar_ssh.py
│   ├── analizar_web.py
│   ├── visualizar.py
│   ├── reporte_ssh.json
│   ├── reporte_web.json
│   ├── graficas/
│   │   ├── top10_ssh.png
│   │   ├── timeline_http.png
│   │   └── heatmap_http.png
│   └── evidencias/
│       ├── SCR-1.1_top10_ssh.png
│       ├── SCR-1.2_timeline_http.png
│       ├── SCR-1.3_heatmap_http.png
│       └── SCR-1.4_ejecucion_scripts.png
├── lab2/
│   ├── local_rules_ssh.xml
│   ├── local_rules_exfil.xml
│   ├── simular_ataque_ssh.py
│   └── evidencias/
│       ├── SCR-2.1_alertas_wazuh.png
│       ├── SCR-2.2_regla_ssh.png
│       ├── SCR-2.3_regla_exfil.png
│       └── alertas_wazuh.txt
├── lab3/
│   ├── network_traffic.csv
│   ├── deteccion_anomalias.ipynb
│   ├── predecir.py
│   ├── modelo_anomalias.pkl
│   ├── top10_anomalias.csv
│   └── evidencias/
│       ├── SCR-3.1_eda.png
│       ├── SCR-3.2_confusion.png
│       ├── SCR-3.3_umbral_f1.png
│       └── SCR-3.4_predecir.png
└── lab4/
    ├── parsear_alertas.py
    ├── dashboard_soc.json
    ├── datasource_config.json
    ├── wazuh_alerts.db
    └── evidencias/
        ├── herramienta_usada.txt
        ├── SCR-4.1_fuente_datos.png
        ├── SCR-4.2_visualizaciones.png
        ├── SCR-4.3_dashboard.png
        └── SCR-4.4_alerta.png
```

---

## Lab 1 — Análisis Forense de Logs con Python

### Descripción
Análisis de logs del sistema para detección de ataques SSH (brute force) y amenazas web (escaneo de directorios, SQL Injection).

### Archivos
- `analizar_ssh.py` — Parsea `auth.log`, cuenta intentos fallidos por IP, genera ranking Top 10 y alerta si una IP supera 50 intentos. Exporta `reporte_ssh.json`.
- `analizar_web.py` — Parsea `access.log`, detecta escaneo de directorios, errores 4xx/5xx por IP e intentos de SQL Injection. Exporta `reporte_web.json`.
- `visualizar.py` — Genera 3 gráficas PNG: barras Top 10 SSH, línea de tiempo HTTP y heatmap por hora/código.

### Instalación de dependencias

```bash
pip3 install matplotlib --break-system-packages
```

### Pasos de reproducción

```bash
cd lab1/
python3 analizar_ssh.py
python3 analizar_web.py
python3 visualizar.py
```

### Resultados obtenidos
- Total IPs atacantes SSH detectadas: ver `reporte_ssh.json`
- Total IPs con escaneo web: ver `reporte_web.json`
- Gráficas generadas en `graficas/`

---

## Lab 2 — Reglas de Correlación en Wazuh

### Descripción
Creación de reglas personalizadas en Wazuh para detección de ataques de fuerza bruta SSH y exfiltración de datos.

### Versión de Wazuh

```bash
/var/ossec/bin/wazuh-control info
```

### Reglas creadas

**`local_rules_ssh.xml`**
- Regla 100001 (nivel 5): captura intentos fallidos SSH
- Regla 100002 (nivel 10): detecta 10+ fallos desde la misma IP en 60 segundos → Brute Force

**`local_rules_exfil.xml`**
- Regla 100010 (nivel 10): tráfico saliente excesivo >500MB
- Regla 100011 (nivel 8): login exitoso fuera de horario laboral
- Regla 100012 (nivel 14): correlación de ambas → Exfiltración de datos crítica

### Pasos de reproducción

```bash
# Copiar reglas a Wazuh
sudo cp lab2/local_rules_ssh.xml /var/ossec/etc/rules/
sudo cp lab2/local_rules_exfil.xml /var/ossec/etc/rules/

# Reiniciar Wazuh
sudo systemctl restart wazuh-manager

# Simular ataque
cd lab2/
python3 simular_ataque_ssh.py

# Ver alertas generadas
sudo tail -100 /var/ossec/logs/alerts/alerts.log
```

### Alertas generadas
- Regla 100011 disparada: Login fuera de horario (nivel 8)
- Regla 100012 disparada: Exfiltración crítica detectada (nivel 14)

---

## Lab 3 — Detección de Anomalías con Machine Learning

### Descripción
Implementación de un modelo de Isolation Forest para detección de tráfico de red anómalo usando el dataset `network_traffic.csv` (10,000 registros).

### Dependencias

```bash
pip3 install jupyter notebook pandas numpy scikit-learn matplotlib seaborn --break-system-packages
```

### Features utilizadas
- `bytes_sent`, `bytes_recv`, `duration_sec`, `packets`
- `protocol_enc` (TCP=0, UDP=1, ICMP=2)
- `bytes_ratio` = bytes_sent / (bytes_recv + 1)
- `bytes_per_pkt` = bytes_sent / (packets + 1)
- `pkts_per_sec` = packets / (duration_sec + 1)
- `dst_port`

### Pasos de reproducción

```bash
# Abrir el notebook
cd lab3/
jupyter notebook deteccion_anomalias.ipynb

# O usar el script de predicción directamente
python3 predecir.py network_traffic.csv
```

### Resultados del modelo
- Algoritmo: Isolation Forest (contamination=0.05, n_estimators=100)
- Métricas: ver `evidencias/SCR-3.2_confusion.png`
- Umbral óptimo F1: ver `evidencias/SCR-3.3_umbral_f1.png`
- Modelo exportado: `modelo_anomalias.pkl`
- Top 10 anomalías: `top10_anomalias.csv`

---

## Lab 4 — Dashboard de Monitoreo SOC

### Descripción
Dashboard de monitoreo SOC construido con Grafana, conectado a una base de datos SQLite con las alertas reales de Wazuh Manager.

### Herramienta utilizada
- **Grafana OSS**
- URL: `http://localhost:3000`
- Plugin: `frser-sqlite-datasource`
- Fuente de datos: `/var/lib/grafana/wazuh_alerts.db`

### Instalación de Grafana

```bash
sudo apt install -y apt-transport-https software-properties-common
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install -y grafana
sudo systemctl enable grafana-server && sudo systemctl start grafana-server
sudo grafana-cli plugins install frser-sqlite-datasource
sudo systemctl restart grafana-server
```

### Pasos de reproducción

```bash
# 1. Copiar el log de alertas de Wazuh
sudo cp /var/ossec/logs/alerts/alerts.log lab4/alerts.log
sudo chown $USER:$USER lab4/alerts.log

# 2. Parsear alertas a SQLite
cd lab4/
python3 parsear_alertas.py

# 3. Mover la DB a la carpeta de Grafana
sudo cp wazuh_alerts.db /var/lib/grafana/wazuh_alerts.db
sudo chown grafana:grafana /var/lib/grafana/wazuh_alerts.db

# 4. Abrir Grafana en http://localhost:3000
# 5. Importar el dashboard desde dashboard_soc.json
```

### Visualizaciones del Dashboard
1. **Alertas por Nivel de Severidad** — Bar chart con niveles 3, 4, 7, 8, 14
2. **Top 10 IPs Atacantes** — Table con fuente, total y nivel máximo
3. **Línea de Alertas por Hora** — Time series con distribución horaria
4. **Distribución por Tipo de Regla** — Pie chart con top 8 tipos de alerta

### Alerta configurada
- Nombre: `Alerta - Nivel Critico Wazuh`
- Condición: COUNT de alertas nivel >= 10 IS ABOVE 0
- Grupo: SOC / SOC-Alertas
- Intervalo de evaluación: 1 minuto

---

## Resumen de Entregables

| Lab | Descripción | Estado |
|---|---|---|
| Lab 1 | Análisis forense SSH + Web + Visualizaciones | ✅ Completo |
| Lab 2 | Reglas Wazuh Brute Force + Exfiltración | ✅ Completo |
| Lab 3 | Isolation Forest + predecir.py | ✅ Completo |
| Lab 4 | Dashboard SOC en Grafana | ✅ Completo |
