import sys
from pathlib import Path

from netmiko import ConnectHandler


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config.settings import SWITCH


def main():
    """Health check manual; pytest puede importar este módulo sin tocar GNS3."""
    conn = ConnectHandler(**SWITCH)
    try:
        conn.enable()
        output = conn.send_command("show mac address-table count")
        print(output)
        print("SSH con Netmiko: OK")
    finally:
        conn.disconnect()


if __name__ == "__main__":
    main()
