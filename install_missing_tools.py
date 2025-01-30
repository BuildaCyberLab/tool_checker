import subprocess
import logging
import re

# Setup Logging
log_file = "tool_check_install.log"
logging.basicConfig(
    filename="install_missing_tools.log",
    filemode="w",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# List of all tools (the same as before)
tools = [
    "nmap", "masscan", "sqlmap", "wpscan", "metasploit", "hydra", "gobuster", "dirb", "aircrack-ng", "john", "hashcat", 
    "netcat", "ssh", "curl", "wget", "nikto", "theharvester", "sublist3r", "reaver", "wireshark", "proxychains", "chisel",
    "enum4linux", "fierce", "dnsrecon", "dnsenum", "whatweb", "shodan", "censys", "spiderfoot",
    "exploitdb", "msfvenom", "impacket", "volatility", "tcpdump",
    "openvas", "nessus", "owasp-zap", "burp-suite", "crunch", "pwnat", "plink", "psftp", "mimikatz", "koadic", "empire",
    "zmap", "arpspoof", "ettercap", "macchanger", "bettercap", "setoolkit", "social-engineer-toolkit", "medusa", "patator", 
    "feroxbuster", "snmpwalk", "snmpcheck", "responder", "yersinia", "hping3", "dnstwist", "cewl", "amass", "recon-ng", 
    "nuclei", "aquatone", "xsser", "sqlninja", "arachni", "golismero", "beef", "wafw00f", "mitmproxy", "sslscan", "testssl.sh", 
    "enumy", "linux-exploit-suggester", "winrm", "powersploit", "veil-framework", "ms14-068", "metagoofil", "footsnmp", 
    "msrpc", "netdiscover", "arp-scan", "ike-scan", "ipmitool"
]

# Check if a tool is installed
def check_tool(tool):
    result = subprocess.run(f"which {tool}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

# Install the tool
def install_tool(tool):
    try:
        if tool == "subfinder":
            subprocess.run("go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", shell=True, check=True)
        elif tool == "amass":
            subprocess.run("go install github.com/OWASP/amass/v3/cmd/amass@latest", shell=True, check=True)
        elif tool == "burp-suite":
            subprocess.run("sudo snap install --classic burpsuite", shell=True, check=True)
        elif tool == "postman":
            subprocess.run("sudo snap install postman", shell=True, check=True)
        elif tool == "wireshark":
            subprocess.run("sudo apt-get install -y wireshark", shell=True, check=True)
        elif tool == "nmap":
            subprocess.run("sudo apt-get install -y nmap", shell=True, check=True)
        elif tool == "metasploit":
            subprocess.run("sudo apt-get install -y metasploit-framework", shell=True, check=True)
        elif tool == "sqlmap":
            subprocess.run("sudo apt-get install -y sqlmap", shell=True, check=True)
        elif tool == "hydra":
            subprocess.run("sudo apt-get install -y hydra", shell=True, check=True)
        elif tool == "gobuster":
            subprocess.run("sudo apt-get install -y gobuster", shell=True, check=True)
        elif tool == "dirb":
            subprocess.run("sudo apt-get install -y dirb", shell=True, check=True)
        elif tool == "john":
            subprocess.run("sudo apt-get install -y john", shell=True, check=True)
        elif tool == "hashcat":
            subprocess.run("sudo apt-get install -y hashcat", shell=True, check=True)
        elif tool == "netcat":
            subprocess.run("sudo apt-get install -y netcat", shell=True, check=True)
        elif tool == "curl":
            subprocess.run("sudo apt-get install -y curl", shell=True, check=True)
        elif tool == "wget":
            subprocess.run("sudo apt-get install -y wget", shell=True, check=True)
        elif tool == "nikto":
            subprocess.run("sudo apt-get install -y nikto", shell=True, check=True)
        elif tool == "reaver":
            subprocess.run("sudo apt-get install -y reaver", shell=True, check=True)
        elif tool == "proxychains":
            subprocess.run("sudo apt-get install -y proxychains", shell=True, check=True)
        elif tool == "chisel":
            subprocess.run("sudo apt-get install -y chisel", shell=True, check=True)
        elif tool == "enum4linux":
            subprocess.run("sudo apt-get install -y enum4linux", shell=True, check=True)
        elif tool == "fierce":
            subprocess.run("sudo apt-get install -y fierce", shell=True, check=True)
        elif tool == "dnsrecon":
            subprocess.run("sudo apt-get install -y dnsrecon", shell=True, check=True)
        elif tool == "dnsenum":
            subprocess.run("sudo apt-get install -y dnsenum", shell=True, check=True)
        elif tool == "whatweb":
            subprocess.run("sudo apt-get install -y whatweb", shell=True, check=True)
        elif tool == "shodan":
            subprocess.run("sudo apt-get install -y shodan", shell=True, check=True)
        elif tool == "censys":
            subprocess.run("sudo apt-get install -y censys", shell=True, check=True)
        elif tool == "spiderfoot":
            subprocess.run("sudo apt-get install -y spiderfoot", shell=True, check=True)
        elif tool == "exploitdb":
            subprocess.run("sudo apt-get install -y exploitdb", shell=True, check=True)
        elif tool == "msfvenom":
            subprocess.run("sudo apt-get install -y msfvenom", shell=True, check=True)
        elif tool == "impacket":
            subprocess.run("sudo apt-get install -y impacket-scripts", shell=True, check=True)
        elif tool == "volatility":
            subprocess.run("sudo apt-get install -y volatility", shell=True, check=True)
        elif tool == "tcpdump":
            subprocess.run("sudo apt-get install -y tcpdump", shell=True, check=True)
        elif tool == "openvas":
            subprocess.run("sudo apt-get install -y openvas", shell=True, check=True)
        elif tool == "nessus":
            subprocess.run("sudo apt-get install -y nessus", shell=True, check=True)
        elif tool == "owasp-zap":
            subprocess.run("sudo apt-get install -y owasp-zap", shell=True, check=True)
        elif tool == "crunch":
            subprocess.run("sudo apt-get install -y crunch", shell=True, check=True)
        elif tool == "pwnat":
            subprocess.run("sudo apt-get install -y pwnat", shell=True, check=True)
        elif tool == "plink":
            subprocess.run("sudo apt-get install -y plink", shell=True, check=True)
        elif tool == "psftp":
            subprocess.run("sudo apt-get install -y psftp", shell=True, check=True)
        elif tool == "mimikatz":
            subprocess.run("sudo apt-get install -y mimikatz", shell=True, check=True)
        elif tool == "koadic":
            subprocess.run("sudo apt-get install -y koadic", shell=True, check=True)
        elif tool == "empire":
            subprocess.run("sudo apt-get install -y empire", shell=True, check=True)
        # Repeat for all other tools in the list...
        
        logging.info(f"[INSTALLED] {tool}")
        print(f"[INSTALLED] {tool}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Failed to install {tool}: {e}")
        print(f"[ERROR] Failed to install {tool}")
        return False

# Read the log file and install missing tools
def install_missing_tools():
    with open(log_file, "r") as file:
        log_lines = file.readlines()

    # Find tools marked as "NOT INSTALLED"
    for line in log_lines:
        if "[NOT INSTALLED]" in line:
            tool_name = re.search(r"\[NOT INSTALLED\] (.*)", line).group(1)
            print(f"Attempting to install {tool_name}...")
            logging.info(f"Attempting to install {tool_name}...")
            if not install_tool(tool_name):
                logging.warning(f"Failed to install {tool_name}.")
            else:
                logging.info(f"Successfully installed {tool_name}.")

if __name__ == "__main__":
    install_missing_tools()
