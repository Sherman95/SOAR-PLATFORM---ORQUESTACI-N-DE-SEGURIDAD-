Ticket 11 — Corregir dependencias y configuración del laboratorio

Prioridad: media

Objetivo

Asegurar que el proyecto pueda instalarse nuevamente en la misma PC o en otra máquina del grupo.

Trabajo
Elegir una versión oficial de Python.
Fijar la versión de PySNMP realmente utilizada.
Fijar PyASN1.
Añadir python-dotenv.
Fijar Netmiko.
Añadir .env a .gitignore.
Crear .env.example.
Eliminar la contraseña del archivo test_ssh.py.
Unificar versión del agente en README, consola y dashboard.
No es obligatorio
Migrar a SNMPv3.
Eliminar totalmente las credenciales simples del laboratorio.
Crear un gestor de secretos.