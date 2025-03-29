import scapy.all as scapy # type: ignore
import socket
import json
import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import requests # type: ignore

def scan_network(ip_range):
    devices = []
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    for element in answered_list:
        ip = element[1].psrc
        device = {
            "ip": ip,
            "mac": element[1].hwsrc,
            "open_ports": scan_ports(ip),
            "vulnerabilities": check_vulnerabilities(ip)
        }
        devices.append(device)
    
    return devices

def scan_ports(ip):
    open_ports = []
    common_ports = [22, 80, 443, 3389, 21, 25, 53]  # SSH, HTTP, HTTPS, RDP, FTP, SMTP, DNS
    
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    return open_ports

def check_vulnerabilities(ip):
    vulnerabilities = []
    
    try:
        response = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key=YOUR_SHODAN_API_KEY")
        data = response.json()
        if "vulns" in data:
            vulnerabilities = data["vulns"]
    except Exception:
        vulnerabilities.append("No se pudo verificar")
    
    return vulnerabilities

def save_results(devices):
    filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All Files", "*.*")])
    if filename:
        with open(filename, "w") as file:
            json.dump(devices, file, indent=4)
        messagebox.showinfo("Guardado", f"Resultados guardados en {filename}")

def start_scan():
    ip_range = entry_ip.get()
    if not ip_range:
        messagebox.showerror("Error", "Ingrese un rango de IPs válido")
        return
    
    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, "Escaneando la red...\n")
    
    def scan_thread():
        devices = scan_network(ip_range)
        result_text.insert(tk.END, json.dumps(devices, indent=4))
        save_button.config(state=tk.NORMAL, command=lambda: save_results(devices))
    
    thread = threading.Thread(target=scan_thread)
    thread.start()

def create_gui():
    global entry_ip, result_text, save_button
    
    root = tk.Tk()
    root.title("NetSec Scanner")
    root.geometry("700x500")
    
    tk.Label(root, text="Ingrese el rango de IPs a escanear:").pack()
    entry_ip = tk.Entry(root, width=30)
    entry_ip.pack()
    
    scan_button = tk.Button(root, text="Escanear", command=start_scan)
    scan_button.pack()
    
    result_text = tk.Text(root, height=20, width=80)
    result_text.pack()
    
    save_button = tk.Button(root, text="Guardar Resultados", state=tk.DISABLED)
    save_button.pack()
    
    root.mainloop()

if __name__ == "__main__":
    create_gui()
