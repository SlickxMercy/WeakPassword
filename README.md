# SlickMercy

## Descripción

SlickMercy es un script en Python diseñado para escanear rangos de IP y detectar cámaras de seguridad Hikvision vulnerables mediante la explotación de la vulnerabilidad CVE-2017-7921 y pruebas de contraseñas débiles. El script incluye una interfaz TUI (Text User Interface) basada en curses para facilitar su uso interactivo.

## Requisitos

- **Termux** (en dispositivos Android)
- **Git**
- **Python 3**
- Las siguientes librerías de Python:
  - requests
  - aiohttp
  - pycryptodome

## Instrucciones de Instalación y Ejecución

Sigue estos pasos para instalar y ejecutar SlickMercy en Termux:

### Paso 1: Instalar Termux

1. Descarga e instala Termux desde [F-Droid](https://f-droid.org/en/packages/com.termux/) (versión recomendada) o desde Google Play Store, según la disponibilidad en tu dispositivo.

### Paso 2: Configurar Termux y Actualizar Paquetes

1. Abre Termux y actualiza la lista de paquetes e instala las últimas versiones:
   ```bash
   apt update && apt upgrade -y
### Paso 3:Instalar Git y Python 
```bash
apt install git python -y
