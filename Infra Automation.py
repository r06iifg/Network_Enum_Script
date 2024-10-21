import subprocess
import os
import argparse
from datetime import datetime

class NmapScanner:
    def __init__(self, ip, base_dir):
        self.ip = ip
        self.base_dir = base_dir
        self.output = f"Scanning {ip}\n"
        self.master_output = ""
        self.master_html_content = ""

    def save_output(self, filename, content):
        """Save content to both specific and master text files."""
        file_path = os.path.join(self.base_dir, filename)
        folder_path = os.path.dirname(file_path)
        os.makedirs(folder_path, exist_ok=True)  # Ensure the folder exists

        with open(file_path, 'a') as f:
            f.write(content)

        # Append to the master text file
        self.master_output += content + "\n"

    def save_html_output(self, filename, content):
        """Save content to both specific and master HTML files."""
        html_path = os.path.join(self.base_dir, filename)
        folder_path = os.path.dirname(html_path)
        os.makedirs(folder_path, exist_ok=True)

        html_content = f"""
<h2>{filename.split('/')[0]} Results</h2>
<pre>{content}</pre>
"""
        with open(html_path, 'w') as f:
            f.write(html_content)

        # Append to the master HTML content
        self.master_html_content += html_content

    def run_command_and_save(self, command, folder, filename):
        """Run a command and save the output."""
        print(f"Running: {command}")
        output = run_command(command)

        if output:
            self.save_output(f'{folder}/{filename}', f"Command: {command}\n{output}")
            self.save_html_output(f'{folder}/{filename.replace(".txt", ".html")}', output)
        else:
            message = f"{folder.split('/')[0]} service is not open or no output available.\n"
            self.save_output(f'{folder}/{filename}', message)
            self.save_html_output(f'{folder}/{filename.replace(".txt", ".html")}', message)

    def run_tcp_scan(self):
        """Run a TCP scan and analyze the results."""
        print(f"Nmap TCP scan is running for {self.ip}...")
        command = f"nmap -sS -p- -sV -O {self.ip}"
        tcp_scan_output = run_command(command)

        self.save_output('tcp_scan_output.txt', tcp_scan_output)
        self.save_html_output('tcp_scan_output.html', tcp_scan_output)

        self.analyze_tcp_scan_results(tcp_scan_output)

    def analyze_tcp_scan_results(self, output):
        """Identify open ports and run corresponding service scans."""
        open_ports = {line.split("/")[0].strip() for line in output.splitlines() if "open" in line}
        ports_to_scan = ['21', '22', '23', '25', '53', '80', '443', '445', '1433', '161', '162']

        for port in ports_to_scan:
            if port in open_ports:
                print(f"Detected open port: {port}")
                self.run_port_specific_scans(port)
            else:
                # Log that the service is not available
                self.run_command_and_save('', port, f'{port}_output.txt')

    def run_port_specific_scans(self, port):
        """Run service-specific scans based on the detected open port."""
        if port == '21':  # FTP
            self.run_command_and_save(f'nmap --script ftp* {self.ip}', 'FTP', 'ftp_output.txt')
        elif port == '22':  # SSH
            self.run_command_and_save(f'sshaudit {self.ip}', 'SSH', 'sshaudit_output.txt')
            self.run_command_and_save(f'nmap --script ssh* {self.ip}', 'SSH', 'ssh_nmap_output.txt')
        elif port == '23':  # Telnet
            self.run_command_and_save(f'nmap --script telnet* {self.ip}', 'Telnet', 'telnet_output.txt')
        elif port == '25':  # SMTP
            self.run_command_and_save(f'nmap --script smtp* {self.ip}', 'SMTP', 'smtp_output.txt')
        elif port == '53':  # DNS
            self.run_command_and_save(f'nmap --script dns* {self.ip}', 'DNS', 'dns_output.txt')
            self.run_command_and_save(f'dig {self.ip}', 'DNS', 'dig_output.txt')
        elif port == '80':  # HTTP
            self.run_command_and_save(f'nmap --script http* {self.ip}', 'HTTP', 'http_nmap_output.txt')
            self.run_command_and_save(f'nikto -h {self.ip}', 'HTTP', 'nikto_output.txt')
            self.run_command_and_save(f'sslscan {self.ip}', 'HTTP', 'sslscan_output.txt')
        elif port == '443':  # HTTPS
            self.run_command_and_save(f'nmap --script https*,ssl* {self.ip}', 'HTTPS', 'https_nmap_output.txt')
            self.run_command_and_save(f'nikto -h {self.ip}', 'HTTPS', 'nikto_https_output.txt')
            self.run_command_and_save(f'sslscan {self.ip}', 'HTTPS', 'sslscan_https_output.txt')
        elif port == '445':  # SMB
            self.run_command_and_save(f'nmap --script smb* {self.ip}', 'SMB', 'smb_output.txt')
            self.run_command_and_save(f'smbmap -H {self.ip}', 'SMB', 'smbmap_output.txt')
            self.run_command_and_save(f'smbclient -L {self.ip}', 'SMB', 'smbclient_output.txt')
        elif port == '1433':  # MSSQL
            self.run_command_and_save(f'nmap --script ms-sql* {self.ip}', 'MSSQL', 'mssql_output.txt')
        elif port in ['161', '162']:  # SNMP
            self.run_command_and_save(f'snmpwalk -v2c -c public {self.ip}', 'SNMP', 'snmpwalk_output.txt')
            self.run_command_and_save(f'nmap --script snmp* {self.ip}', 'SNMP', 'snmp_nmap_output.txt')

def run_command(command):
    """Run a shell command and return the output."""
    if not command:
        return ""  # If no command, return empty output

    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running command: {command}\n{result.stderr.strip()}")
            return ""
        return result.stdout.strip()
    except Exception as e:
        print(f"Exception occurred: {str(e)}")
        return ""

def main():
    parser = argparse.ArgumentParser(description="Automated Nmap scanning with service-specific follow-ups.")
    args = parser.parse_args()

    if not os.path.exists('iplist.txt'):
        print("iplist.txt not found.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_folder = f"scan_results_{timestamp}"
    os.makedirs(base_folder, exist_ok=True)

    with open('iplist.txt', 'r') as file:
        ips = [ip.strip() for ip in file if ip.strip()]

    for ip in ips:
        scanner = NmapScanner(ip, base_folder)
        scanner.run_tcp_scan()

        # Save master output files
        scanner.save_output('master/master_output.txt', scanner.master_output)
        scanner.save_html_output('master/master_output.html', scanner.master_html_content)

    print("Scanning completed. Results saved.")

if __name__ == "__main__":
    main()
