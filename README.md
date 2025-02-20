# SlickMercy

## Descripción

SlickMercy es un script en Python diseñado para escanear rangos de IP y detectar cámaras de seguridad Hikvision vulnerables mediante la explotación de la vulnerabilidad CVE-2017-7921 y pruebas de contraseñas débiles.

## Requisitos

- **Termux** (en dispositivos Android)
- **Git**
- **Python 3**
- Las siguientes librerías de Python:
  - requests
  - aiohttp
  - pycryptodome

## Instrucciones de Instalación y Ejecución

Sigue estos pasos para instalar y ejecutar SlickMercy.py en Termux:

### Paso 1: Instalar Termux

1. Descarga e instala Termux desde [F-Droid](https://f-droid.org/en/packages/com.termux/) (versión recomendada)

### Paso 2: Configurar Termux y Actualizar Paquetes

1. Abre Termux y actualiza la lista de paquetes e instala las últimas versiones:
   ```bash
   apt update && apt upgrade -y
   
### Paso 3:Instalar Git y Python 

1. Instala Git y Python con el siguiente comando:
```bash
   apt install git python -y
```
### Paso 4: Clonar el Repositorio
1. Clona el repositorio desde GitHub 
 ```bash
cd storage/downloads/
ls
git clone https://github.com/SlickxMercy/WeakPassword
   ```
### Paso 5: Instalar Dependencias de Python
1.Instala las dependencias necesarias para que el script funcione correctamente:
```bash
pip install requests aiohttp pycryptodome
```
### Paso 6 Ejecutar Script 
1. acceder a la carpeta y ejecutar script
```bash
cd storage/downloads/WeakPassword
ls
python SlickMercy.py
```


