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

### **2. Windap Search**
- **Command:** `python3 /home/kali/Tools/windapsearch/windapsearch.py -d <domain>`
- **Tool:** `windapsearch`
- **Description:** Enumerates LDAP details using Windapsearch.

### **3. GetUserSPNs (Impacket)**
- **Command:** `impacket-GetUserSPNs -request <domain>`
- **Tool:** `impacket-scripts`
- **Description:** Enumerates Kerberos service accounts.

### **4. GetNPUsers (Impacket)**
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

### **11. Run BloodHound Python Script**
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

### **14. Kerbrute User Enumeration**
- **Command:** `kerbrute userenum -d <domain> -U <wordlist>`
- **Tool:** `kerbrute`
- **Description:** Enumerates valid usernames in Active Directory.

### **15. Setup Ligolo Tunneling**
- **Tool:** `ligolo`
- **Description:** Sets up Ligolo tunneling for pivoting.

### **16. Add Ligolo Port Forwarding Listeners**
- **Tool:** `ligolo`
- **Description:** Configures Ligolo port forwarding for lateral movement.

### **17. SNMP Walk**
- **Command:** `snmpwalk -v1 -c public <target-ip>`
- **Tool:** `snmp`
- **Description:** Queries SNMP-enabled devices for information.

### **18. Create Reverse Shell**
- **Tool:** `msfvenom`
- **Description:** Generates reverse shell payloads for exploitation.

### **19. impacket-psexec**
- **Command:** `impacket-psexec <domain>/<user>:<pass>@<target-ip>`
- **Tool:** `impacket-scripts`
- **Description:** Executes commands remotely via SMB.

### **20. impacket-smbexec**
- **Command:** `impacket-smbexec <domain>/<user>:<pass>@<target-ip>`
- **Tool:** `impacket-scripts`
- **Description:** Executes commands remotely using SMB without needing administrator privileges.

### **21. Evil-WinRM**
- **Command:** `evil-winrm -i <target-ip> -u <user> -p <pass>`
- **Tool:** `evil-winrm`
- **Description:** Provides an interactive WinRM shell.

### **22. BloodHound Queries**
- **Description:** Provides useful Cypher queries for BloodHound analysis.

### **23. MSSQL/MySQL Connection**
- **Tool:** `impacket-mssqlclient, mysql-client`
- **Description:** Connects to MSSQL/MySQL databases.

### **24. Gobuster Directory Brute-Forcing**
- **Tool:** `gobuster`
- **Description:** Performs directory brute-forcing.

### **25. FFUF Web Fuzzing**
- **Tool:** `ffuf`
- **Description:** Fuzzes web applications for hidden paths.

### **26. Common Web Exploitation Tips**
- **Description:** Provides a reference for SQL injection, XSS, and LFI.

### **27. Explain xp_cmdshell Enabling**
- **Description:** Guides on enabling `xp_cmdshell` in MSSQL.

### **28. Create Wordlist with Cewl**
- **Tool:** `cewl`
- **Description:** Generates wordlists from website content.

### **29. RDP and Admin Setup Explanation**
- **Description:** Explains how to enable RDP and add users to admin groups.

## Contributing
Contributions are welcome! Fork the repository and submit a pull request.

## License
This project is licensed under the MIT License.

