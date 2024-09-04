import subprocess
import os
from datetime import datetime

class NmapScanner:
    def __init__(self, ip):
        self.ip = ip
        self.output = f"TCP Scan for {ip}\n"

    def run_tcp_scan(self):
        nmap_tcp_command = f"nmap -sS -p- -sV -sC -O -Pn {self.ip}"
        nmap_tcp_output = run_command(nmap_tcp_command)
        print(f"TCP Scan Output:\n{nmap_tcp_output}")  # Debugging output
        self.output += nmap_tcp_output + "\n"

    def check_open_ports(self):
        for line in self.output.splitlines():
            if "open" in line:
                port = line.split("/")[0].strip()
                self.output += f"\nPort {port} is open.\n"
                self.run_port_specific_scans(port)

    def run_port_specific_scans(self, port):
        if port == '21':
            self.output += run_command(f'nmap --script ftp* {self.ip}') + "\n"
        elif port == '22':
            self.output += run_command(f'nmap --script ssh* {self.ip}') + "\n"
        elif port == '23':
            self.output += run_command(f'nmap --script telnet* {self.ip}') + "\n"
        elif port == '25':
            self.output += run_command(f'nmap --script smtp* {self.ip}') + "\n"
        elif port == '53':
            self.output += run_command(f'nmap --script dns* {self.ip}') + "\n"
            self.output += run_command(f'dig {self.ip}') + "\n"
        elif port == '80':
            self.output += run_command(f'nikto -h {self.ip}') + "\n"
            self.output += run_command(f'sslscan -h {self.ip}') + "\n"
            self.output += run_command(f'nmap --script http* {self.ip}') + "\n"
        elif port == '443':
            self.output += run_command(f'nikto -h {self.ip}') + "\n"
            self.output += run_command(f'sslscan -h {self.ip}') + "\n"
            self.output += run_command(f'nmap --script https*,ssl* {self.ip}') + "\n"
        elif port == '445':
            self.output += run_command(f'smbmap -h {self.ip}') + "\n"
            self.output += run_command(f'smbclient -L {self.ip}') + "\n"
            self.output += run_command(f'nmap --script smb* {self.ip}') + "\n"
        elif port == '1443':
            self.output += run_command(f'nmap --script ms-sql* {self.ip}') + "\n"
        elif port in ['161', '162']:
            self.output += run_command(f'snmpwalk -v2c -c public {self.ip}') + "\n"
            self.output += run_command(f'nmap --script snmp* {self.ip}') + "\n"

class Scanner:
    def __init__(self, ip):
        self.ip = ip
        self.output = ""

    def run(self):
        nmap_scanner = NmapScanner(self.ip)
        nmap_scanner.run_tcp_scan()
        nmap_scanner.check_open_ports()
        self.output += nmap_scanner.output

def run_command(command):
    """Run a shell command and return the output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running command: {command}\n{result.stderr.strip()}")  # Print error if command fails
        return result.stdout.strip()
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return str(e)

def main():
    # Check if the input file exists
    if not os.path.exists('iplist.txt'):
        print("iplist.txt not found.")
        return

    # Create output filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = f"scan_results_{timestamp}.txt"

    with open('iplist.txt', 'r') as file:
        ips = file.readlines()

    results = []
    for ip in ips:
        ip = ip.strip()
        if ip:
            scanner = Scanner(ip)
            scanner.run()
            results.append(scanner.output)

    # Save results to a text file
    with open(output_filename, 'w') as result_file:
        for result in results:
            result_file.write(result + "=" * 50 + "\n")

    print(f"Scanning completed. Results saved in {output_filename}")

if __name__ == "__main__":
    main()
