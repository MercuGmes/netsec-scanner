# 🔍 NetSec Scanner

NetSec Scanner es una herramienta de escaneo de red con interfaz gráfica en Python. Permite descubrir dispositivos en una red local, identificar puertos abiertos y verificar vulnerabilidades mediante la API de Shodan.

## 📌 Características
✅ Escaneo de dispositivos en la red local 📡  
✅ Detección de puertos abiertos en los dispositivos 📍  
✅ Integración con la API de Shodan para encontrar vulnerabilidades 🔥  
✅ Interfaz gráfica amigable con Tkinter 🎨  
✅ Exportación de resultados en formato JSON 📄  

## 🚀 Instalación
### 1️⃣ Clonar el repositorio
```bash
git clone https://github.com/MercuGmes/netsec-scanner.git
cd netsec-scanner
```

### 2️⃣ Instalar dependencias
Asegúrate de tener Python 3 instalado, luego ejecuta:
```bash
pip install -r requirements.txt
```

Si tienes problemas con `scapy` en Windows, instala Npcap desde:
🔗 [Npcap Download](https://npcap.com/#download)

### 3️⃣ Configurar API de Shodan (Opcional)
Si quieres usar la detección de vulnerabilidades, obtén una API key de Shodan en [Shodan.io](https://shodan.io) y reemplaza `YOUR_SHODAN_API_KEY` en el código.

## 🎯 Uso
Ejecuta el escáner con:
```bash
python netsec_scanner.py
```

Luego, ingresa el rango de IPs a escanear, como:
```
192.168.1.1/24
```

## 🛠 Dependencias
- `scapy` → Para escaneo de red
- `socket` → Para detección de puertos
- `requests` → Para consultar la API de Shodan
- `tkinter` → Para la interfaz gráfica
- `json` → Para exportar resultados

Instala todo con:
```bash
pip install scapy requests tk
```

## 📜 Licencia
Este proyecto está bajo la licencia MIT. ¡Úsalo con responsabilidad! ⚖️

---
💻 Desarrollado por [MercuGmes]

