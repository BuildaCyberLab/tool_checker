import os
import logging

# Configure logging
log_file = "tool_check.log"
logging.basicConfig(
    filename=log_file,
    filemode="w",
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

def check_tool(tool_name):
    """Check if a tool is installed by looking for it in the system PATH."""
    result = os.system(f"which {tool_name} > /dev/null 2>&1")
    return result == 0

def main():
    tools = [
        "nmap", "masscan", "sqlmap", "wpscan", "metasploit", "hydra",
        "gobuster", "dirb", "aircrack-ng", "john", "hashcat", "netcat",
        "ssh", "curl", "wget", "nikto", "theharvester", "sublist3r",
        "reaver", "wireshark", "proxychains", "chisel",

        # Enumeration & Discovery
        "enum4linux", "fierce", "dnsrecon", "dnsenum", "whatweb", "shodan", 
        "censys", "spiderfoot",

        # Exploitation
        "exploitdb", "msfvenom", "impacket", "volatility", "tcpdump",

        # Vulnerability Scanning
        "openvas", "nessus", "owasp-zap", "burp-suite",

        # Password Cracking
        "crunch",

        # Post-Exploitation
        "pwnat", "plink", "psftp", "mimikatz", "koadic", "empire",

        # Additional Tools
        "zmap", "arpspoof", "ettercap", "macchanger", "bettercap",
        "setoolkit", "social-engineer-toolkit", "medusa", "patator", "feroxbuster",
        "snmpwalk", "snmpcheck", "responder", "yersinia", "hping3",
        "dnstwist", "cewl", "amass", "recon-ng", "nuclei",
        "aquatone", "xsser", "sqlninja", "arachni", "golismero",
        "beef", "wafw00f", "mitmproxy", "sslscan", "testssl.sh",
        "enumy", "linux-exploit-suggester", "winrm", "powersploit",
        "veil-framework", "ms14-068", "metagoofil", "footsnmp",
        "msrpc", "netdiscover", "arp-scan", "ike-scan", "ipmitool"
    ]

    print("Checking installed tools...")

    for tool in tools:
        if check_tool(tool):
            print(f"[INSTALLED] {tool}")
            logging.info(f"[INSTALLED] {tool}")
        else:
            print(f"[NOT INSTALLED] {tool}")
            logging.warning(f"[NOT INSTALLED] {tool}")

    print(f"Results logged to {log_file}")

if __name__ == "__main__":
    main()
