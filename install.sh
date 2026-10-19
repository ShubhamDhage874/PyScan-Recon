#!/bin/bash
# =============================================================================
# PyScan-Recon One-Click Installer for Kali Linux, Ubuntu, Debian & Termux
# Author: Shubham Dhage (https://github.com/ShubhamDhage874)
# =============================================================================

echo "[*] Setting up PyScan-Recon Network Scanner..."

# Detect Environment: Termux vs Standard Linux
if [ -d "/data/data/com.termux" ]; then
    echo "[+] Termux environment detected."
    pkg update -y && pkg install python -y
    pip install -r requirements.txt
    chmod +x pyscan.py
    ln -sf "$(pwd)/pyscan.py" "$PREFIX/bin/pyscan"
    echo "[✓] Installation complete! You can now run the tool by typing: pyscan"
else
    echo "[+] Linux environment detected (Kali/Debian/Ubuntu)."
    sudo apt-get update -y
    sudo apt-get install python3 python3-pip -y
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
    chmod +x pyscan.py
    sudo ln -sf "$(pwd)/pyscan.py" /usr/local/bin/pyscan 2>/dev/null || ln -sf "$(pwd)/pyscan.py" ~/.local/bin/pyscan
    echo "[✓] Installation complete! You can now run the tool from anywhere by typing: pyscan"
fi

echo "[*] Launching interactive menu..."
python3 pyscan.py
