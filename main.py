import psutil
import hashlib
import os
import time
import socket

def banner():
    print("\033[1;32m" + r"""
  _________________   __________.____     ____ ______________ ______________________   _____      _____   
 /   _____/\_____  \  \______   \    |   |    |   \_   _____/ \__    ___/\_   _____/  /  _  \    /     \  
 \_____  \  /  ____/   |    |  _/    |   |    |   /|    __)_    |    |    |    __)_  /  /_\  \  /  \ /  \ 
 /        \/       \   |    |   \    |___|    |  / |        \   |    |    |        \/    |    \/    Y    \
/_______  /\_______ \  |______  /_______ \______/ /_______  /   |____|   /_______  /\____|__  /\____|__  /
        \/         \/         \/        \/                \/                     \/         \/         \/ 

                            WELCOME TO S2 BLUE TEAM MULTITOOL v1.0
                            Built by S2 vez AND Akira
    """ + "\033[0m")  # Reset color after the banner

# Colors
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"

# 1. List Running Processes
def list_processes():
    print(f"{YELLOW}\n[+] Running Processes:{RESET}")
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            print(f"{GREEN}PID: {proc.info['pid']} - Name: {proc.info['name']}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error listing processes: {e}{RESET}")

# 2. List Open Network Connections
def list_connections():
    print(f"{YELLOW}\n[+] Open Network Connections:{RESET}")
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                print(f"{GREEN}Local: {laddr} --> Remote: {raddr}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error listing connections: {e}{RESET}")

# 3. File Hashing (SHA256)
def hash_file(file_path):
    if not os.path.isfile(file_path):
        print(f"{RED}[!] File not found.{RESET}")
        return
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        print(f"{YELLOW}\n[+] SHA256 Hash: {GREEN}{sha256_hash.hexdigest()}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error hashing file: {e}{RESET}")

# 4. Log Searching
def search_logs(log_dir, keyword):
    if not os.path.isdir(log_dir):
        print(f"{RED}[!] Log directory not found.{RESET}")
        return
    print(f"{YELLOW}\n[+] Searching for '{keyword}' in logs under {log_dir}{RESET}")
    try:
        for root, dirs, files in os.walk(log_dir):
            for file in files:
                if file.endswith(".log") or file.endswith(".txt"):
                    path = os.path.join(root, file)
                    with open(path, 'r', errors='ignore') as f:
                        for line in f:
                            if keyword in line:
                                print(f"{GREEN}[{file}] {line.strip()}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error searching logs: {e}{RESET}")

# 5. Live Process Monitor
def live_process_monitor():
    print(f"{YELLOW}\n[+] Starting Live Process Monitor (Press CTRL+C to stop)...{RESET}")
    try:
        while True:
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"{GREEN}[LIVE] Running Processes:{RESET}")
            for proc in psutil.process_iter(['pid', 'name']):
                print(f"{YELLOW}PID: {proc.info['pid']} - Name: {proc.info['name']}{RESET}")
            time.sleep(3)
    except KeyboardInterrupt:
        print(f"{YELLOW}\n[+] Live monitoring stopped.{RESET}")

# 6. Suspicious Process Detection
def detect_suspicious_processes():
    print(f"{YELLOW}\n[+] Detecting suspicious processes...{RESET}")
    suspicious_names = ['mimikatz', 'powershell', 'meterpreter', 'nc.exe', 'cmd.exe']
    found = False
    for proc in psutil.process_iter(['pid', 'name', 'ppid']):
        try:
            if any(name in proc.info['name'].lower() for name in suspicious_names):
                print(f"{RED}[SUSPICIOUS] PID: {proc.info['pid']} - Name: {proc.info['name']}{RESET}")
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    if not found:
        print(f"{GREEN}[+] No suspicious processes found.{RESET}")

# 7. IP Reputation Check
def check_ip_reputation():
    ip = input(f"{YELLOW}Enter IP address to check: {RESET}").strip()
    bad_ips = ['1.1.1.1', '8.8.8.8', '123.45.67.89']  # Example dummy bad IPs
    try:
        socket.inet_aton(ip)
        if ip in bad_ips:
            print(f"{RED}[ALERT] IP {ip} is known suspicious!{RESET}")
        else:
            print(f"{GREEN}[+] IP {ip} seems clean (local check).{RESET}")
    except socket.error:
        print(f"{RED}[!] Invalid IP address.{RESET}")

# Menu for User Interaction
def menu():
    while True:
        print(f"""{YELLOW}        
        ================================
           S2 BLUE TEAM MAIN MENU
        ================================
        [1] List Running Processes
        [2] List Open Network Connections
        [3] Hash a File (SHA256)
        [4] Search Logs for Keyword
        [5] Start Live Process Monitor
        [6] Detect Suspicious Processes
        [7] Check IP Reputation
        [8] Exit
        {RESET}""")
        choice = input(f"{YELLOW}Select an option: {RESET}").strip()

        if choice == '1':
            list_processes()
        elif choice == '2':
            list_connections()
        elif choice == '3':
            path = input(f"{YELLOW}Enter file path: {RESET}").strip()
            hash_file(path)
        elif choice == '4':
            path = input(f"{YELLOW}Enter log directory path: {RESET}").strip()
            keyword = input(f"{YELLOW}Enter keyword to search for: {RESET}").strip()
            search_logs(path, keyword)
        elif choice == '5':
            live_process_monitor()
        elif choice == '6':
            detect_suspicious_processes()
        elif choice == '7':
            check_ip_reputation()
        elif choice == '8':
            print(f"{GREEN}\n[+] Exiting S2 BLUE TEAM Multitool. Stay Safe! 🛡️{RESET}")
            break
        else:
            print(f"{RED}[!] Invalid choice. Please select a valid option.{RESET}")

if __name__ == "__main__":
    banner()
    menu()
