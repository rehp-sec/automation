Para utilizar este script es fundamental registrar una app en Azure y asociarlo con un rol personalizado de Azure que sólo permita permisos de lectura sobre las IPs Publicas.

Una vez realices lo anterior no olvides completar la siguiente información en el script sobre Azure:

# Configuración de Azure
TENANT_ID = 'xxx'
CLIENT_ID = 'xxx'
CLIENT_SECRET = 'xxx'
SUBSCRIPTION_ID = 'xxx'

Adicionalmente deberás rellenar la información correspondiente a tu servidor SMTP:

# Configuración del servidor SMTP
SERVIDOR_SMTP = 'smtp.test.com'
PUERTO_SMTP = 587
REMITENTE = 'test@test.cl'
CONTRASENA = 'test123'

Finalmente, para ejecutar el script debes considerar los siguientes argumentos, por ejemplo:

python3 scan-azure.py --ips x.x.x.x/24 x.x.x.x --destinatario test@test.cl

*En adición a las IPs públicas de Azure que actualizara constantemente el script también puedes agregar IPs publicas adicionales al ejecutar el comando.
