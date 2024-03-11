import platform
import subprocess
import random
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import ARP, Ether, srp
manufacturers = {
    "Lenovo": ["00:11:22:33:44:AA", "00:55:BB:66:77:88"],
    "HP": ["00:90:E8:F1:23:45", "C0:49:C7:31:68:BC"],
    "Dell": ["00:A0:C9:80:00:11", "70:E6:9A:FF:FE:00"],
    "ASUS": ["00:E0:4C:11:22:33", "AC:EC:00:E0:4C:11"],
    "Apple": ["00:16:7F:00:00:00", "F0:00:0C:93:C6:4F"],
    "Acer": ["00:1E:67:00:11:22", "74:2E:7E:F8:3A:9C"]
}

# Global variable to store logs
logs = []

# Function to log actions
def log_action(action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logs.append(f"[{timestamp}] {action}")

# Function to display logs
def display_logs():
    log_text = "\n".join(logs)
    if log_text:
        messagebox.showinfo("Logs", log_text)
    else:
        messagebox.showinfo("Logs", "No logs available.")

# Function to perform ARP scan
def arp_scan():
    log_action("Doing ARP Scan")
    ip_range = "192.168.43.0/24"
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({"IP": element[1].psrc, "MAC": element[1].hwsrc})

    return devices

# Function to display ARP scan results
def display_arp_results():
    devices = arp_scan()
    if devices:
        result_text = "ARP Scan Results:\n"
        for device in devices:
            result_text += f"IP: {device['IP']}, MAC: {device['MAC']}\n"
        messagebox.showinfo("ARP Scan Results", result_text)
    else:
        messagebox.showinfo("ARP Scan Results", "No devices found.")

# Function to select a random MAC address from the provided manufacturer
def select_mac_address(manufacturer):
    if manufacturer not in manufacturers:
        return None
    mac_address = random.choice(manufacturers[manufacturer])
    log_action(f"Selected MAC address for {manufacturer}: {mac_address}")
    return mac_address

# Function to handle the button click event for selecting MAC addresses
def select_mac_button_click():
    global manufacturer_var  # Access the global variable
    manufacturer = manufacturer_var.get()
    mac_address = select_mac_address(manufacturer)
    if mac_address:
        messagebox.showinfo("Selected MAC Address", f"Selected MAC address for {manufacturer}: {mac_address}")
        change_mac_address(mac_address)  # Change MAC address to the selected one
    else:
        messagebox.showerror("Error", f"Manufacturer '{manufacturer}' not found.")

# Function to change MAC address to the specified one
def change_mac_address(mac_address):
    system = platform.system()
    if system == "Windows":
        subprocess.run(["netsh", "interface", "set", "interface", "name=Ethernet", "admin=disable"])
        subprocess.run(["netsh", "interface", "set", "address", "name=Ethernet", "source=static", "addr=", mac_address])
        subprocess.run(["netsh", "interface", "set", "interface", "name=Ethernet", "admin=enable"])
    elif system == "Linux":
        subprocess.run(["ifconfig", "eth0", "down"])
        subprocess.run(["ifconfig", "eth0", "hw", "ether", mac_address])
        subprocess.run(["ifconfig", "eth0", "up"])
    else:
        messagebox.showerror("Error", "Unsupported operating system.")

# Function to display system information
def display_system_info():
    # Get system information
    system_info = {
        "Developer Name": "Suleman Rehman",
        "Roll Number": "19I-1667",
        "Section": "CS-B",
        "Degree": "BS Cyber Security",
        "Campus": "FAST NUCES ISLAMABAD",
        "Course Subject": "Ethical Hacking Concepts & Practices",
        "Current Date and Time": get_current_date_time()
    }

    # Display system information
    info_text = ""
    for key, value in system_info.items():
        info_text += f"{key}: {value}\n"
    messagebox.showinfo("System Information", info_text)

# Function to get current date and time
def get_current_date_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Function to display current MAC addresses
def display_current_mac():
    system = platform.system()
    if system == "Windows":
        result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True)
        output = result.stdout
        # Parsing MAC addresses from ipconfig output
        mac_addresses = [line.split()[-1] for line in output.split('\n') if "Physical Address" in line]
        if not mac_addresses:
            messagebox.showerror("Error", "Failed to retrieve MAC addresses.")
        else:
            messagebox.showinfo("Current MAC Addresses", "\n".join(mac_addresses))
    elif system == "Linux":
        result = subprocess.run(["ifconfig"], capture_output=True, text=True)
        output = result.stdout
        # Parsing MAC addresses from ifconfig output
        mac_addresses = [line.split()[1] for line in output.split('\n') if "ether" in line]
        if not mac_addresses:
            messagebox.showerror("Error", "Failed to retrieve MAC addresses.")
        else:
            messagebox.showinfo("Current MAC Addresses", "\n".join(mac_addresses))
    else:
        messagebox.showerror("Error", "Unsupported operating system.")

# Function to generate a random MAC address in a valid format
def generate_random_mac():
    # Generate random hexadecimal digits for the MAC address
    random_mac = [random.choice("0123456789ABCDEF") for _ in range(12)]
    
    # Join pairs of hexadecimal digits with colons
    mac_address = ':'.join(''.join(random_mac[i:i+2]) for i in range(0, 12, 2))
    
    return mac_address


# Function to change MAC address to a random one
def change_to_random_mac():
    system = platform.system()
    new_mac = generate_random_mac()
    if system == "Windows":
        subprocess.run(["netsh", "interface", "set", "interface", "name=Ethernet", "admin=disable"])
        subprocess.run(["netsh", "interface", "set", "address", "name=Ethernet", "source=random"])
        subprocess.run(["netsh", "interface", "set", "interface", "name=Ethernet", "admin=enable"])
    elif system == "Linux":
        subprocess.run(["ifconfig", "eth0", "down"])
        subprocess.run(["ifconfig", "eth0", "hw", "ether", new_mac])
        subprocess.run(["ifconfig", "eth0", "up"])
    else:
        messagebox.showerror("Error", "Unsupported operating system.")
        return
    log_action(f"MAC address changed to: {new_mac}")
    messagebox.showinfo("Success", f"MAC address changed to: {new_mac}")

# Function to reset MAC address to default
def reset_mac_to_default():
    system = platform.system()
    if system == "Windows":
        subprocess.run(["netsh", "interface", "set", "interface", "name=Ethernet", "admin=disable"])
        subprocess.run(["netsh", "interface", "set", "address", "name=Ethernet", "source=original"])
        subprocess.run(["netsh", "interface", "set", "interface", "name=Ethernet", "admin=enable"])
    elif system == "Linux":
        # Replace "original_mac_address" with the actual original MAC address
        original_mac_address = "00:11:22:33:44:55"
        subprocess.run(["ifconfig", "eth0", "down"])
        subprocess.run(["ifconfig", "eth0", "hw", "ether", original_mac_address])
        subprocess.run(["ifconfig", "eth0", "up"])
    else:
        messagebox.showerror("Error", "Unsupported operating system.")

import tkinter as tk
from tkinter import ttk, messagebox

# Function to create the Graphical User Interface (GUI)
def create_gui():
    global manufacturer_var
    root = tk.Tk()
    root.title("MAC Address Spoofer")

    # Set window size and position
    window_width = 500
    window_height = 500
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_coordinate = (screen_width - window_width) // 2
    y_coordinate = (screen_height - window_height) // 2
    root.geometry(f"{window_width}x{window_height}+{x_coordinate}+{y_coordinate}")

    # Create and apply styles
    style = ttk.Style()
    style.configure("TFrame", background="#f0f0f0")
    style.configure("TLabel", background="#f0f0f0")
    style.configure("TButton", background="#007bff", foreground="#ffffff", font=("Arial", 12))

    # Manufacturer selection label and combobox
    frame = ttk.Frame(root, padding="20")
    frame.pack(fill="both", expand=True)
    
    manufacturer_label = ttk.Label(frame, text="Select Manufacturer:")
    manufacturer_label.grid(row=0, column=0, padx=10, pady=5)

    manufacturer_var = tk.StringVar()
    manufacturer_combobox = ttk.Combobox(frame, textvariable=manufacturer_var, values=list(manufacturers.keys()))
    manufacturer_combobox.grid(row=0, column=1, padx=10, pady=5)

    select_mac_button = ttk.Button(frame, text="Select MAC Address", command=select_mac_button_click)
    select_mac_button.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="we")

    # Button to trigger ARP scan
    arp_scan_button = ttk.Button(frame, text="ARP Scan", command=display_arp_results)
    arp_scan_button.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="we")

    # Buttons for various actions
    ttk.Button(frame, text="Display System Information", command=display_system_info).grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="we")

    ttk.Button(frame, text="Display Current MAC Addresses", command=display_current_mac).grid(row=6, column=0, columnspan=2, padx=10, pady=5, sticky="we")

    ttk.Button(frame, text="Change to Random MAC", command=change_to_random_mac).grid(row=8, column=0, columnspan=2, padx=10, pady=5, sticky="we")

    ttk.Button(frame, text="Reset MAC Address to Default", command=reset_mac_to_default).grid(row=10, column=0, columnspan=2, padx=10, pady=5, sticky="we")

    # Button to display logs
    ttk.Button(frame, text="Logs", command=display_logs).grid(row=11, column=0, columnspan=2, padx=10, pady=5, sticky="we")

    root.mainloop()

# Call the function to create the GUI
create_gui()
