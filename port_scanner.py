import socket
from datetime import datetime

target = input("Enter target IP or hostname: ")

try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("Invalid hostname or IP address.")
    exit()

print("\n" + "=" * 50)
print("        PYTHON NETWORK PORT SCANNER")
print("=" * 50)
print("Target:", target_ip)
print("Scanning ports 1-1024...")
print("Started:", datetime.now().strftime("%H:%M:%S"))
print("=" * 50)

open_ports = []

for port in range(1, 1025):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)

    result = sock.connect_ex((target_ip, port))

    if result == 0:
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "Unknown"

        print(f"[OPEN] Port {port:<5} | Service: {service}")
        open_ports.append(port)

    sock.close()

print("=" * 50)
print("Scan completed!")
print("Open ports found:", len(open_ports))
print("Finished:", datetime.now().strftime("%H:%M:%S"))
print("=" * 50)
