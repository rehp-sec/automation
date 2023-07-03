Script de Detección Automática de Puertos Vulnerables en Azure
Antes de comenzar, asegúrate de tener instaladas las siguientes bibliotecas:

bash
Copy code
pip install azure-mgmt-compute azure-mgmt-storage azure-mgmt-resource azure-keyvault-secrets azure-storage-blob python-nmap azure-identity azure-mgmt-network
Configuración
Antes de utilizar este script, es fundamental realizar los siguientes pasos de configuración:

Registra una aplicación en Azure y asígnale un rol personalizado que permita únicamente permisos de lectura sobre las IPs públicas.

Completa la siguiente información en el script relacionada a Azure:

python
Copy code
TENANT_ID = 'xxx'
CLIENT_ID = 'xxx'
CLIENT_SECRET = 'xxx'
SUBSCRIPTION_ID = 'xxx'
Rellena la información correspondiente a tu servidor SMTP para el envío de correos:
python
Copy code
SERVIDOR_SMTP = 'smtp.test.com'
PUERTO_SMTP = 587
REMITENTE = 'test@test.cl'
CONTRASENA = 'test123'
Ejecución
Para ejecutar el script, considera los siguientes argumentos:

bash
Copy code
python3 scan-azure.py --ips x.x.x.x/24 x.x.x.x --destinatario test@test.cl
Además de las IPs públicas de Azure que se actualizarán constantemente, puedes agregar IPs públicas adicionales al ejecutar el comando. Estas IPs pueden ser, por ejemplo, las IPs públicas de tus enlaces de internet en tu entorno local (on-premise).

Recuerda que el script realizará automáticamente la detección de puertos vulnerables y enviará notificaciones por correo electrónico con los resultados obtenidos.
