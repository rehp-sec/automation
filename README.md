Inicialmente instala estas librerias:

pip3 install nmap python-nmap scapy azure azure-mgmt-compute azure-mgmt-storage azure-mgmt-resource azure-keyvault-secrets azure-storage-blob azure-identity azure-mgmt-network

Para utilizar este script es fundamental registrar una app en Azure y asociarlo con un rol personalizado de Azure que sólo tenga permisos de lectura sobre las IPs Publicas.

Una vez realices lo anterior no olvides completar la siguiente información en el script sobre Azure (TENANT_ID, CLIENT_ID, CLIENT_SECRET y SUBSCRIPTION_ID).

Adicionalmente deberás rellenar la información correspondiente a tu servidor SMTP (SERVIDOR_SMTP, PUERTO_SMTP, REMITENTE y CONTRASENA).

Finalmente, para ejecutar el script debes considerar los siguientes argumentos, por ejemplo:

python3 scan-azure.py --ips x.x.x.x/24 x.x.x.x --destinatario test@test.cl

*En adición a las IPs públicas de Azure que actualizara constantemente el script también puedes agregar IPs publicas adicionales al ejecutar el comando (que por ejemplo podrian ser las IPs publicas de tus enlaces a internet de tu ambiente on-premise).
