import subprocess
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# Setup Logging
log_file = "tool_check_install.log"
logging.basicConfig(
    filename=log_file,
    filemode="w",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

# List of all tools
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
        elif tool == "zmap":
            subprocess.run("sudo apt-get install -y zmap", shell=True, check=True)
        elif tool == "arpspoof":
            subprocess.run("sudo apt-get install -y arpspoof", shell=True, check=True)
        elif tool == "ettercap":
            subprocess.run("sudo apt-get install -y ettercap", shell=True, check=True)
        elif tool == "macchanger":
            subprocess.run("sudo apt-get install -y macchanger", shell=True, check=True)
        elif tool == "bettercap":
            subprocess.run("sudo apt-get install -y bettercap", shell=True, check=True)
        elif tool == "setoolkit":
            subprocess.run("sudo apt-get install -y setoolkit", shell=True, check=True)
        elif tool == "social-engineer-toolkit":
            subprocess.run("sudo apt-get install -y social-engineer-toolkit", shell=True, check=True)
        elif tool == "medusa":
            subprocess.run("sudo apt-get install -y medusa", shell=True, check=True)
        elif tool == "patator":
            subprocess.run("sudo apt-get install -y patator", shell=True, check=True)
        elif tool == "feroxbuster":
            subprocess.run("sudo apt-get install -y feroxbuster", shell=True, check=True)
        elif tool == "snmpwalk":
            subprocess.run("sudo apt-get install -y snmpwalk", shell=True, check=True)
        elif tool == "snmpcheck":
            subprocess.run("sudo apt-get install -y snmpcheck", shell=True, check=True)
        elif tool == "responder":
            subprocess.run("sudo apt-get install -y responder", shell=True, check=True)
        elif tool == "yersinia":
            subprocess.run("sudo apt-get install -y yersinia", shell=True, check=True)
        elif tool == "hping3":
            subprocess.run("sudo apt-get install -y hping3", shell=True, check=True)
        elif tool == "dnstwist":
            subprocess.run("sudo apt-get install -y dnstwist", shell=True, check=True)
        elif tool == "cewl":
            subprocess.run("sudo apt-get install -y cewl", shell=True, check=True)
        elif tool == "recon-ng":
            subprocess.run("sudo apt-get install -y recon-ng", shell=True, check=True)
        elif tool == "nuclei":
            subprocess.run("sudo apt-get install -y nuclei", shell=True, check=True)
        elif tool == "aquatone":
            subprocess.run("sudo apt-get install -y aquatone", shell=True, check=True)
        elif tool == "xsser":
            subprocess.run("sudo apt-get install -y xsser", shell=True, check=True)
        elif tool == "sqlninja":
            subprocess.run("sudo apt-get install -y sqlninja", shell=True, check=True)
        elif tool == "arachni":
            subprocess.run("sudo apt-get install -y arachni", shell=True, check=True)
        elif tool == "golismero":
            subprocess.run("sudo apt-get install -y golismero", shell=True, check=True)
        elif tool == "beef":
            subprocess.run("sudo apt-get install -y beef", shell=True, check=True)
        elif tool == "wafw00f":
            subprocess.run("sudo apt-get install -y wafw00f", shell=True, check=True)
        elif tool == "mitmproxy":
            subprocess.run("sudo apt-get install -y mitmproxy", shell=True, check=True)
        elif tool == "sslscan":
            subprocess.run("sudo apt-get install -y sslscan", shell=True, check=True)
        elif tool == "testssl.sh":
            subprocess.run("sudo apt-get install -y testssl.sh", shell=True, check=True)
        elif tool == "enumy":
            subprocess.run("sudo apt-get install -y enumy", shell=True, check=True)
        elif tool == "linux-exploit-suggester":
            subprocess.run("sudo apt-get install -y linux-exploit-suggester", shell=True, check=True)
        elif tool == "winrm":
            subprocess.run("sudo apt-get install -y winrm", shell=True, check=True)
        elif tool == "powersploit":
            subprocess.run("sudo apt-get install -y powersploit", shell=True, check=True)
        elif tool == "veil-framework":
            subprocess.run("sudo apt-get install -y veil-framework", shell=True, check=True)
        elif tool == "ms14-068":
            subprocess.run("sudo apt-get install -y ms14-068", shell=True, check=True)
        elif tool == "metagoofil":
            subprocess.run("sudo apt-get install -y metagoofil", shell=True, check=True)
        elif tool == "footsnmp":
            subprocess.run("sudo apt-get install -y footsnmp", shell=True, check=True)
        elif tool == "msrpc":
            subprocess.run("sudo apt-get install -y msrpc", shell=True, check=True)
        elif tool == "netdiscover":
            subprocess.run("sudo apt-get install -y netdiscover", shell=True, check=True)
        elif tool == "arp-scan":
            subprocess.run("sudo apt-get install -y arp-scan", shell=True, check=True)
        elif tool == "ike-scan":
            subprocess.run("sudo apt-get install -y ike-scan", shell=True, check=True)
        elif tool == "ipmitool":
            subprocess.run("sudo apt-get install -y ipmitool", shell=True, check=True)
        logging.info(f"[INSTALLED] {tool}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Failed to install {tool}: {e}")
        return False

# Main function
def main():
    with ThreadPoolExecutor() as executor:
        futures = []
        for tool in tools:
            if check_tool(tool):
                print(f"[INSTALLED] {tool}")
                logging.info(f"[INSTALLED] {tool}")
            else:
                print(f"[NOT INSTALLED] {tool}")
                logging.warning(f"[NOT INSTALLED] {tool}")
                futures.append(executor.submit(install_tool, tool))

        for future in tqdm(futures, desc="Installing Tools"):
            result = future.result()
            if not result:
                logging.warning(f"[FAILED] Tool installation failed.")

    print(f"Results logged to {log_file}")

if __name__ == "__main__":
    main()
