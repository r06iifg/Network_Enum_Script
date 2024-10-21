#!/bin/bash

# Update the package list
echo "Updating package list..."
sudo apt-get update -y

# Install ssh-audit
echo "Installing ssh-audit..."
sudo apt-get install -y ssh-audit

# Install dig (from dnsutils package)
echo "Installing dig..."
sudo apt-get install -y dnsutils

# Install Nikto
echo "Installing Nikto..."
sudo apt-get install -y nikto

# Install sslscan
echo "Installing sslscan..."
sudo apt-get install -y sslscan

# Install smbmap
echo "Installing smbmap..."
sudo apt-get install -y smbmap

# Install enum4linux-ng (this might need to be cloned from GitHub)
echo "Installing enum4linux-ng..."
sudo apt-get install -y python3-pip  # Install pip3 if needed
pip3 install git+https://github.com/cddmp/enum4linux-ng.git

# Install snmpwalk (part of the snmp package)
echo "Installing snmpwalk..."
sudo apt-get install -y snmp

# Install nmap
echo "Installing nmap..."
sudo apt-get install -y nmap

# Confirm installation of all tools
echo "Verifying installed tools..."
for tool in ssh-audit dig nikto sslscan smbmap enum4linux-ng snmpwalk nmap; do
    if command -v $tool &> /dev/null; then
        echo "$tool installed successfully"
    else
        echo "Error: $tool is not installed"
    fi
done

echo "All requested tools have been installed."
