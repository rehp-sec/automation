import argparse
import nmap
import re
import smtplib
import threading
import time
from email.mime.text import MIMEText
from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient

# Configuración de programas vulnerables y palabras clave
PROGRAMAS_VULNERABLES = {
    "SSH": [r'openssh', r'bitvise', r'dropbear', r'sshwindows', r'freeftpd', r'wincsp'],
    "Telnet": [r'telnet', r'indigo', r'tftpd64', r'anyterm'],
    "HTTP": [r'apache', r'nginx', r'httpd', r'iis', r'lighttpd', r'abyss', r'jexus'],
    "DNS": [r'bind', r'microsoftdns', r'dnsmasq', r'powerdns'],
    "SNMP": [r'snmp', r'net-snmp', r'windows-snmp'],
    "SMB": [r'samba', r'microsoft-ds'],
    "RDP": [r'rdp', r'remote desktop', r'freerdp', r'xrdp'],
    "FTP": [r'ftp', r'vsftpd', r'proftpd', r'pure-ftpd', r'filezilla', r'war-ftpd'],
    "MySQL": [r'mysql', r'mariadb'],
    "TFTP": [r'tftp', r'atftpd', r'tftpd', r'tftpd32'],
    "NTP": [r'ntp', r'openntpd', r'chrony']
}

# Configuración del servidor SMTP
SERVIDOR_SMTP = 'smtp.test.com'
PUERTO_SMTP = 587
REMITENTE = 'test@test.cl'
CONTRASENA = 'test123'

# Configuración de Azure
TENANT_ID = 'xxx'
CLIENT_ID = 'xxx'
CLIENT_SECRET = 'xxx'
SUBSCRIPTION_ID = 'xxx'

ips_publicas_azure = []
ips_externas = []

def obtener_ips_publicas_azure():
    global ips_publicas_azure
    credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    network_client = NetworkManagementClient(credential, SUBSCRIPTION_ID)
    todas_ips_publicas = network_client.public_ip_addresses.list_all()
    ips_publicas_azure = [ip.ip_address for ip in todas_ips_publicas if ip.ip_address]

def actualizar_ips():
    while True:
        obtener_ips_publicas_azure()
        time.sleep(30)

def enviar_correo(ip, puerto, servicio, os, destinatario, nombre_programa):
    asunto = 'Puerto vulnerable detectado'
    cuerpo = f"Se encontró el puerto {puerto} ({servicio}, {nombre_programa}) abierto en la IP {ip} con sistema operativo {os}."
    mensaje = MIMEText(cuerpo)
    mensaje['Subject'] = asunto
    mensaje['From'] = REMITENTE
    mensaje['To'] = destinatario
    try:
        with smtplib.SMTP(SERVIDOR_SMTP, PUERTO_SMTP) as servidor_smtp:
            servidor_smtp.starttls()
            servidor_smtp.login(REMITENTE, CONTRASENA)
            servidor_smtp.sendmail(REMITENTE, destinatario, mensaje.as_string())
        print("Correo enviado con éxito.")
    except smtplib.SMTPException as e:
        print(f"Error al enviar el correo: {e}")

def buscar_programas_vulnerables(resultado):
    for servicio, expresiones in PROGRAMAS_VULNERABLES.items():
        for expresion in expresiones:
            if re.search(expresion, resultado, re.IGNORECASE):
                return servicio
    return None

def obtener_os(nm, host):
    try:
        resultados_os = nm[host]['osmatch']
        if resultados_os:
            return resultados_os[0]['name']
        else:
            return 'Sistema operativo desconocido'
    except KeyError:
        return 'Detección de sistema operativo fallida'

def escanear_puertos(destinatario):
    nm = nmap.PortScanner()
    for ip in ips_publicas_azure + ips_externas:
        def escanear_ip(ip):
            while True:
                print(f"Escanenado puertos en la IP: {ip}")
                nm.scan(hosts=ip, arguments='-p 1-65535 -sV -O -n -Pn -T5 --min-parallelism 100')
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        for puerto in nm[host][proto].keys():
                            if nm[host][proto][puerto]['state'] == 'open':
                                os = obtener_os(nm, host)
                                nombre_programa = buscar_programas_vulnerables(nm[host][proto][puerto]['product'])
                                if nombre_programa is not None:
                                    print(f"¡Puerto vulnerable detectado!\nIP: {ip}\nSistema operativo: {os}")
                                    enviar_correo(ip, puerto, proto, os, destinatario, nm[host][proto][puerto]['product'])
                time.sleep(60)
        threading.Thread(target=escanear_ip, args=(ip,)).start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script para detección de puertos abiertos y servicios vulnerables.')
    parser.add_argument('--destinatario', required=True, help='Dirección de correo a la que se enviarán las notificaciones.')
    parser.add_argument('--ips', nargs='*', default=[], help='Añadir direcciones IP públicas adicionales a escanear.')
    args = parser.parse_args()

    ips_externas.extend(args.ips)

    obtener_ips_publicas_azure()
    threading.Thread(target=actualizar_ips).start()
    escanear_puertos(args.destinatario)

