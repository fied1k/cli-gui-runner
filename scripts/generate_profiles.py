import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cheatsheet_engine import OffensiveRamenHTMLParser, CheatSheetProfile, CommandItem

def main():
    os.makedirs("profiles", exist_ok=True)

    # 1. Kismet Profile from fetched HTML
    if os.path.exists("kismet_raw.html"):
        with open("kismet_raw.html", "r", encoding="utf-8") as f:
            html = f.read()
        p = OffensiveRamenHTMLParser()
        p.profile.sheet_id = "kismet"
        p.profile.title = "Kismet Wireless"
        p.profile.source = "https://offensiveramen.com/cheatsheets/kismet"
        p.profile.default_file = "profiles/kismet.txt"
        p.feed(html)
        p.profile.save_json("profiles/kismet.json")
        with open("profiles/kismet.txt", "w", encoding="utf-8") as f:
            f.write(p.profile.export_commands_txt())
        print("Generated profiles/kismet.json & profiles/kismet.txt")

    # 2. Nmap Profile
    nmap_prof = CheatSheetProfile(
        sheet_id="nmap",
        title="Nmap Network Scanner",
        source="https://offensiveramen.com/cheatsheets/nmap",
        default_file="profiles/nmap.txt"
    )
    nmap_cmds = [
        ("nmap (top 1000)", "nmap <target>", "Basic TCP port scan probing the top 1,000 most common ports", "Basic Scans"),
        ("-sn", "nmap -sn <target>", "Host discovery ping scan without port scanning", "Basic Scans"),
        ("-Pn", "nmap -Pn <target>", "Skip host discovery ping probes; treat all targets as online", "Basic Scans"),
        ("-p-", "nmap -p- <target>", "Scan all 65,535 TCP ports", "Port Specifications"),
        ("-p <Port>", "nmap -p <port> <target>", "Scan specific port numbers or ranges (e.g. 22,80,443)", "Port Specifications"),
        ("-F", "nmap -F <target>", "Fast scan probing the top 100 most common ports", "Port Specifications"),
        ("-sS", "nmap -sS <target>", "TCP SYN stealth scan (half-open, default with root)", "Scan Techniques"),
        ("-sT", "nmap -sT <target>", "TCP connect scan (full three-way handshake, no root needed)", "Scan Techniques"),
        ("-sU", "nmap -sU <target>", "UDP port scan for open UDP services (DNS, SNMP, DHCP)", "Scan Techniques"),
        ("-sA", "nmap -sA <target>", "TCP ACK scan to map firewall rulesets and filtered ports", "Scan Techniques"),
        ("-sW", "nmap -sW <target>", "TCP Window scan to determine open vs filtered ports", "Scan Techniques"),
        ("-sV", "nmap -sV <target>", "Probe open ports to determine service name and version info", "Service & OS Detection"),
        ("-sV (Aggressive)", "nmap -sV --version-intensity 5 <target>", "Aggressive service version detection probing deeper", "Service & OS Detection"),
        ("-O", "nmap -O <target>", "Remote operating system detection via TCP/IP fingerprinting", "Service & OS Detection"),
        ("-A", "nmap -A <target>", "Aggressive scan (OS detection, version scan, script scanning, traceroute)", "Service & OS Detection"),
        ("-T0 (Paranoid)", "nmap -T0 <target>", "Paranoid timing for serial IDS evasion", "Timing & Performance"),
        ("-T2 (Polite)", "nmap -T2 <target>", "Polite timing consuming less target bandwidth", "Timing & Performance"),
        ("-T4 (Aggressive)", "nmap -T4 <target>", "Aggressive timing for faster scans on reliable networks", "Timing & Performance"),
        ("-T5 (Insane)", "nmap -T5 <target>", "Extremely fast timing for high-speed networks", "Timing & Performance"),
        ("--script=default", "nmap -sC <target>", "Run default safe NSE scripts", "NSE Script Engine"),
        ("--script=vuln", "nmap --script=vuln <target>", "Check target for known CVE vulnerabilities", "NSE Script Engine"),
        ("--script=auth", "nmap --script=auth <target>", "Run authentication and credential checks", "NSE Script Engine"),
        ("--script=discovery", "nmap --script=discovery <target>", "Run network discovery and directory enumeration scripts", "NSE Script Engine"),
        ("--script=safe", "nmap --script=safe <target>", "Run safe non-intrusive scripts", "NSE Script Engine"),
        ("-oN", "nmap -oN <output_file> <target>", "Save scan results in normal human-readable format", "Output & Formats"),
        ("-oX", "nmap -oX <output_xml> <target>", "Save scan results in XML format", "Output & Formats"),
        ("-oG", "nmap -oG <output_gnmap> <target>", "Save scan results in grepable format", "Output & Formats"),
        ("-oA", "nmap -oA <output_prefix> <target>", "Save scan results in all three major formats (Nmap, XML, Grepable)", "Output & Formats"),
        ("-f (Fragment)", "nmap -f <target>", "Fragment packets to evade simple packet filters", "Firewall & IDS Evasion"),
        ("-D (Decoys)", "nmap -D RND:5 <target>", "Cloak scan using 5 random decoy IP addresses", "Firewall & IDS Evasion"),
        ("-S (Spoof)", "nmap -S <spoofed_ip> <target>", "Spoof source IP address", "Firewall & IDS Evasion"),
        ("-g (Port 53)", "nmap -g 53 <target>", "Use source port 53 (DNS) for outbound probes", "Firewall & IDS Evasion")
    ]
    for sw, tm, ds, cat in nmap_cmds:
        nmap_prof.add_command(CommandItem(sw, tm, ds, cat))
    nmap_prof.save_json("profiles/nmap.json")
    with open("profiles/nmap.txt", "w", encoding="utf-8") as f:
        f.write(nmap_prof.export_commands_txt())
    print("Generated profiles/nmap.json & profiles/nmap.txt")

    # 3. TShark Profile
    tshark_prof = CheatSheetProfile(
        sheet_id="tshark",
        title="Wireshark & TShark",
        default_file="profiles/tshark.txt"
    )
    tshark_cmds = [
        ("-D (List Ifaces)", "tshark -D", "List all available network capture interfaces with index numbers", "Capture Operations"),
        ("-i <interface>", "tshark -i <interface>", "Capture and stream live traffic to stdout from specified interface", "Capture Operations"),
        ("-c <packets>", "tshark -i <interface> -c <packet_count>", "Stop capture automatically after receiving specified packet count", "Capture Operations"),
        ("-w <file>", "tshark -i <interface> -w <output_pcap>", "Save raw packet data directly to pcap file for later analysis", "File IO & Conversion"),
        ("-r <file>", "tshark -r <input_pcap>", "Read and analyze existing packet capture file", "File IO & Conversion"),
        ("-Y (Filter)", 'tshark -r <input_pcap> -Y "<display_filter>"', "Filter packet analysis using standard Wireshark display filter syntax", "Filtering & Analysis")
    ]
    for sw, tm, ds, cat in tshark_cmds:
        tshark_prof.add_command(CommandItem(sw, tm, ds, cat))
    tshark_prof.save_json("profiles/tshark.json")
    with open("profiles/tshark.txt", "w", encoding="utf-8") as f:
        f.write(tshark_prof.export_commands_txt())
    print("Generated profiles/tshark.json & profiles/tshark.txt")

    # 4. General Profile
    gen_prof = CheatSheetProfile(
        sheet_id="general",
        title="General Quick Tools",
        default_file="commands.txt"
    )
    gen_cmds = [
        ("Ping Host", "ping -c 4 <IP_or_Hostname>", "Send 4 ICMP echo requests to a target", "Network Diagnostics"),
        ("Port Scan (Nmap)", "nmap -sV -p <Port_Range> <Target_IP>", "Scan specific ports and detect versions", "Network Diagnostics"),
        ("Find Files", 'find <Directory> -name "*<Search_Term>*"', "Search for files recursively in directory tree", "File Utilities"),
        ("Check Disk Space", "df -h", "Show current disk usage in human-readable format", "System Diagnostics"),
        ("Custom cURL", "curl -I -X <HTTP_Method> <URL>", "Fetch HTTP response headers from a URL", "Web Requests"),
    ]
    for sw, tm, ds, cat in gen_cmds:
        gen_prof.add_command(CommandItem(sw, tm, ds, cat))
    gen_prof.save_json("profiles/general.json")
    print("Generated profiles/general.json")

if __name__ == "__main__":
    main()
