from netmiko import ConnectHandler

sw = {
    "device_type": "cisco_ios",
    "host":        "192.168.1.10",
    "username":    "admin",
    "password":    "cisco123",
    "secret":      "cisco123",
}

conn = ConnectHandler(**sw)
conn.enable()
output = conn.send_command("show mac address-table count")
print(output)
conn.disconnect()
print("SSH con Netmiko: OK")
