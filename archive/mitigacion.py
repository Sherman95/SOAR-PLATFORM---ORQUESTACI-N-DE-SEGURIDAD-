from netmiko import ConnectHandler
import time

# Credenciales exactas de tu Switch IOU
SWITCH = {
    "device_type": "cisco_ios",
    "host":        "192.168.1.10",
    "username":    "admin",
    "password":    "cisco123",
    "secret":      "cisco123",
    "timeout":     30,        # subir de 10 a 30
    "conn_timeout": 30,
}

# Variables según tu topología
PUERTO_ATACANTE = 'Ethernet0/3'
UMBRAL_MACS = 50  # Si un puerto tiene más de 50 MACs, es un ataque

def defender_red():
    print("[*] Conectando al Switch Core (192.168.1.10)...")
    try:
        net_connect = ConnectHandler(**cisco_switch)
        net_connect.enable()
        print("[+] Conexión exitosa. Monitoreando tráfico malicioso...\n")

        while True:
            # Revisar la tabla MAC específicamente en el puerto del atacante
            comando = f"show mac address-table dynamic interface {PUERTO_ATACANTE}"
            salida = net_connect.send_command(comando)
            
            # Contar cuántas direcciones MAC hay en ese puerto
            lineas_mac = [linea for linea in salida.split('\n') if 'DYNAMIC' in linea.upper()]
            cantidad_macs = len(lineas_mac)
            
            print(f"[Vigilancia] {cantidad_macs} MACs detectadas en {PUERTO_ATACANTE}")

            # Lógica de Mitigación
            if cantidad_macs > UMBRAL_MACS:
                print(f"\n[!!!] ALERTA CRÍTICA: MAC Flooding detectado en {PUERTO_ATACANTE}.")
                print("[*] Iniciando contención. Aislando el puerto...")
                
                comandos_mitigacion = [
                    f"interface {PUERTO_ATACANTE}",
                    "shutdown"
                ]
                net_connect.send_config_set(comandos_mitigacion)
                
                print(f"[+] AMENAZA NEUTRALIZADA: El puerto {PUERTO_ATACANTE} ha sido apagado (Administratively Down).")
                break 
            
            time.sleep(3) # Esperar 3 segundos para el próximo escaneo

        net_connect.disconnect()

    except Exception as e:
        print(f"[-] Error de conexión: {e}")

if __name__ == "__main__":
    defender_red()