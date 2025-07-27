
# Parental Control System using ARP Spoofing

This project implements a **Parental Control System** designed to manage and restrict internet access for specific devices on a local network by leveraging ARP Spoofing. By intercepting and manipulating network traffic, it enables granular control over network connectivity and content filtering on targeted devices. The system demonstrates key network security and management concepts suitable for educational and controlled ethical use.

---

## ✨ Features

- **ARP Spoofing:**  
  Positions the controller as a Man-in-the-Middle (MITM) on the LAN, intercepting communications between devices and the router.

- **Network Scanning:**  
  Discover all active devices on your local network, including their IP and MAC addresses (`network_scanner.py`).

- **Internet Blocking / Net Cut:**  
  Block or restore internet access for specific client devices, effectively isolating them from network resources (`net_cut.py`).

- **Website/Content Blocking:**  
  Filter specific URLs or domains by editing the `block_list.txt` file, allowing custom parental/content restrictions.

- **Packet Sniffing:**  
  Capture, monitor, and analyze network traffic for logging, analysis, or identifying unauthorized access attempts (`packet_sniffer.py`).

- **Centralized Control:**  
  The main script (`project.py`) integrates these modules for seamless operation.

---

## 🧠 How it Works

- **ARP Spoofing:**  
  The system sends forged ARP replies, tricking both the router and the target device into associating the parent's device with each other's MAC address. This reroutes all communication through the controller.

- **Traffic Interception:**  
  Intercepts all inbound and outbound packets for the controlled device.

- **Filtering and Blocking:**  
  Inspects packets, checks against a block list, and decides whether to forward, drop, or modify each one.

- **Internet Cut-Off:**  
  Drops all intercepted packets for selected devices to disconnect them entirely.

- **Packet Sniffing:**  
  Simultaneously monitors and logs traffic for analysis or auditing.

---

## 💻 Technologies Used

- **Python 3.x**
- **Scapy:** For building/sending ARP packets and sniffing network traffic.
- **NetfilterQueue:** Integrates with Linux netfilter for packet inspection and modification.
- **NetAddr:** For network address manipulation.
- **(Linux OS required):** High-level privileges and kernel support needed for packet manipulation.

---

## 📁 Project Structure

```
parental-control-system-using-arp-spoofing/
└── parental controle system_ICN/
    ├── .vscode/
    ├── __pycache__/
    ├── arp_spoof.py
    ├── block_list.txt
    ├── net_cut.py
    ├── network_scanner.py
    ├── packet_sniffer.py
    ├── project.py
    ├── requirements.txt
    └── todo.txt
```

---

## ⚙️ Setup and Installation

### Prerequisites

- **Linux OS recommended**
- **Root/sudo privileges required**
- **Python 3.x installed**

### Install

1. **Clone the Repository:**
    ```
    git clone 
    cd parental-control-system-using-arp-spoofing/parental controle system_ICN
    ```

2. **Install Dependencies:**
    ```
    pip install -r requirements.txt
    ```

---

## ▶️ Usage

1. **Scan the Network:**  
   ```
   sudo python network_scanner.py
   ```
   Identify target device and router IP/MAC addresses.

2. **Configure Block List:**  
   - Edit `block_list.txt` to specify URLs/domains to block.

3. **Start Parental Control:**  
   ```
   sudo python project.py  
   ```
   Refer to script help for custom options.

4. **Stop Safely:**  
   Use Ctrl+C and ensure scripts restore the original ARP tables to prevent lingering network issues.

---

## ⚠️ Important Disclaimer & Ethical Considerations

- **Educational Use Only:**  
  This project is for demonstration and educational purposes.
- **Permission Required:**  
  Do NOT deploy or test without explicit permission from the network owner and users.
- **Legal and Responsible Use:**  
  Unauthorized ARP spoofing is illegal and disruptive.

---

## 💡 Conclusion

The **Parental Control System using ARP Spoofing** offers a powerful and practical illustration of core network security concepts. By applying techniques like ARP spoofing, packet sniffing, and selective network disruption, it provides tangible exposure to both the risks of MITM attacks and methods for administrative control over LAN environments. While aimed at parental control, its architecture is relevant for anyone exploring network defense, monitoring, or penetration testing. Use with care and always with explicit authorization.

