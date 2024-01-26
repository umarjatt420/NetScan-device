import socket
from scapy.all import ARP, Ether, srp
from tabulate import tabulate

def get_connected_devices(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices
    
def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown"
    return hostname
ip_range = "192.168.10.0/24"
connected_devices = get_connected_devices(ip_range)
table = []
for device in connected_devices:
    ip = device["ip"]
    mac = device["mac"]
    hostname = get_hostname(ip)
    table.append([ip, mac, hostname])
headers = ["IP Address", "MAC Address", "Hostname"]
print(tabulate(table, headers, tablefmt="grid"))