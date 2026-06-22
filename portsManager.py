#!/usr/bin/env python3
"""
PortGuard - Modern CLI Port Scanner & Manager
A lightweight tool to scan, monitor, and manage network ports
"""

import socket
import subprocess
import sys
import os
import time
import json
import threading
from datetime import datetime
from collections import defaultdict
import platform
import signal
import ctypes
from pathlib import Path

# Color codes for modern terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    END = '\033[0m'

# Well-known ports database
WELL_KNOWN_PORTS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
    69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    119: "NNTP", 123: "NTP", 135: "RPC", 137: "NetBIOS Name",
    138: "NetBIOS Datagram", 139: "NetBIOS Session", 143: "IMAP",
    161: "SNMP", 162: "SNMP Trap", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD",
    520: "RIP", 521: "RIPng", 540: "UUCP", 554: "RTSP",
    587: "SMTP Submission", 631: "IPP", 636: "LDAPS", 873: "rsync",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1434: "MSSQL Browser", 1521: "Oracle",
    1701: "L2TP", 1723: "PPTP", 1812: "RADIUS", 1883: "MQTT",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL", 2181: "ZooKeeper",
    2375: "Docker", 2376: "Docker TLS", 3128: "Squid",
    3306: "MySQL", 3389: "RDP", 3478: "STUN", 4000: "Diablo II",
    4444: "Metasploit", 4500: "IPSec NAT", 5000: "UPnP",
    5222: "XMPP", 5269: "XMPP Server", 5353: "mDNS",
    5432: "PostgreSQL", 5555: "Android ADB", 5632: "pcAnywhere",
    5672: "RabbitMQ", 5900: "VNC", 5938: "TeamViewer",
    5985: "WinRM HTTP", 5986: "WinRM HTTPS", 6379: "Redis",
    6667: "IRC", 6881: "BitTorrent", 7474: "Neo4j",
    8000: "HTTP Alt", 8080: "HTTP Proxy", 8443: "HTTPS Alt",
    8888: "Jupyter", 9000: "SonarQube", 9092: "Kafka",
    9200: "Elasticsearch", 9300: "Elasticsearch Node",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB Shard",
    28017: "MongoDB Web", 50000: "SAP", 50070: "Hadoop"
}

class PortGuard:
    def __init__(self):
        self.os_type = platform.system()
        self.config_dir = Path.home() / '.portguard'
        self.config_file = self.config_dir / 'config.json'
        self.blocked_ports_file = self.config_dir / 'blocked_ports.json'
        self.ensure_directories()
        self.blocked_ports = self.load_blocked_ports()
        self.refresh_interval = 5
        self.running = True
        
    def ensure_directories(self):
        """Create necessary directories"""
        self.config_dir.mkdir(exist_ok=True)
        
    def load_blocked_ports(self):
        """Load blocked ports from file"""
        try:
            if self.blocked_ports_file.exists():
                with open(self.blocked_ports_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        return []
    
    def save_blocked_ports(self):
        """Save blocked ports to file"""
        with open(self.blocked_ports_file, 'w') as f:
            json.dump(self.blocked_ports, f, indent=2)
    
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if self.os_type == 'Windows' else 'clear')
    
    def print_banner(self):
        """Display application banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║                    {Colors.WHITE}🛡️  PortsManager v1.0{Colors.CYAN}                    ║
║          {Colors.DIM}Modern CLI Port Scanner & Manager{Colors.CYAN}              ║
╚══════════════════════════════════════════════════════════╝
{Colors.END}"""
        print(banner)
    
    def is_admin(self):
        """Check if running with administrator privileges"""
        try:
            if self.os_type == 'Windows':
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def scan_ports(self, start_port=1, end_port=65535, only_active=False):
        """Scan ports and return results"""
        results = {
            'well_known': [],
            'registered': [],
            'dynamic': [],
            'listening': []
        }
        
        if only_active:
            return self.get_active_connections()
        
        print(f"{Colors.YELLOW}Scanning ports {start_port}-{end_port}...{Colors.END}")
        
        for port in range(start_port, min(end_port + 1, 65536)):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex(('127.0.0.1', port))
                
                if result == 0:
                    service = WELL_KNOWN_PORTS.get(port, "")
                    
                    port_info = {
                        'port': port,
                        'service': service,
                        'status': 'OPEN',
                        'category': self.get_port_category(port)
                    }
                    
                    if port <= 1023:
                        results['well_known'].append(port_info)
                    elif port <= 49151:
                        results['registered'].append(port_info)
                    else:
                        results['dynamic'].append(port_info)
                
                sock.close()
                
                if port % 1000 == 0:
                    print(f"{Colors.DIM}Progress: {port}/{end_port}{Colors.END}", end='\r')
                    
            except:
                pass
        
        return results
    
    def get_active_connections(self):
        """Get active network connections"""
        results = {
            'well_known': [],
            'registered': [],
            'dynamic': [],
            'listening': []
        }
        
        try:
            if self.os_type == 'Windows':
                cmd = 'netstat -ano'
            else:
                cmd = 'netstat -tlnp'
                
            output = subprocess.check_output(cmd, shell=True, text=True)
            
            for line in output.split('\n'):
                if 'LISTEN' in line or 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr = parts[1]
                        if ':' in addr:
                            try:
                                port = int(addr.split(':')[-1])
                                service = WELL_KNOWN_PORTS.get(port, "")
                                port_info = {
                                    'port': port,
                                    'service': service,
                                    'status': 'LISTENING',
                                    'category': self.get_port_category(port),
                                    'connection': line
                                }
                                
                                if port <= 1023:
                                    results['well_known'].append(port_info)
                                elif port <= 49151:
                                    results['registered'].append(port_info)
                                else:
                                    results['dynamic'].append(port_info)
                            except:
                                pass
        except Exception as e:
            print(f"{Colors.RED}Error getting connections: {e}{Colors.END}")
        
        return results
    
    def get_port_category(self, port):
        """Determine port category"""
        if port <= 1023:
            return "Well-Known Port"
        elif port <= 49151:
            return "Registered Port"
        else:
            return "Dynamic/Private Port"
    
    def display_results(self, results):
        """Display scan results in organized format"""
        self.clear_screen()
        self.print_banner()
        
        print(f"{Colors.BOLD}{Colors.WHITE}📊 Port Scan Results{Colors.END}\n")
        
        categories = [
            ('Well-Known Ports (0-1023)', 'well_known', Colors.RED),
            ('Registered Ports (1024-49151)', 'registered', Colors.YELLOW),
            ('Dynamic Ports (49152-65535)', 'dynamic', Colors.GREEN)
        ]
        
        total_open = 0
        
        for title, key, color in categories:
            ports = results.get(key, [])
            if ports:
                print(f"{color}{Colors.BOLD}▸ {title}{Colors.END}")
                print(f"{Colors.DIM}╭{'─' * 78}╮{Colors.END}")
                print(f"{Colors.DIM}│{Colors.END} {Colors.WHITE}{'Port':<8} {'Service':<30} {'Status':<12} Category{'':<18}{Colors.DIM}│{Colors.END}")
                print(f"{Colors.DIM}├{'─' * 78}┤{Colors.END}")
                
                for port_info in ports[:10]:  # Show first 10 per category
                    status_color = Colors.GREEN if port_info['status'] == 'LISTENING' else Colors.RED
                    service = port_info['service'] or 'Unknown'
                    print(f"{Colors.DIM}│{Colors.END} {color}{port_info['port']:<8}{Colors.END} "
                          f"{Colors.WHITE}{service[:30]:<30}{Colors.END} "
                          f"{status_color}{port_info['status']:<12}{Colors.END} "
                          f"{Colors.DIM}{port_info['category']:<26}{Colors.DIM}│{Colors.END}")
                
                if len(ports) > 10:
                    print(f"{Colors.DIM}│{Colors.END} {Colors.DIM}... and {len(ports) - 10} more ports{Colors.END}{' ' * 55}{Colors.DIM}│{Colors.END}")
                
                print(f"{Colors.DIM}╰{'─' * 78}╯{Colors.END}\n")
                total_open += len(ports)
        
        print(f"{Colors.BOLD}Total Open/Active Ports: {Colors.CYAN}{total_open}{Colors.END}")
        
        if self.blocked_ports:
            print(f"{Colors.YELLOW}⚠️  Blocked Ports: {len(self.blocked_ports)}{Colors.END}")
    
    def close_port(self, port):
        """Close a specific port using firewall rules"""
        if not self.is_admin():
            print(f"{Colors.RED}❌ Administrator privileges required to close ports{Colors.END}")
            return False
        
        try:
            if self.os_type == 'Windows':
                cmd = f'netsh advfirewall firewall add rule name="PortGuard_Block_{port}" dir=in action=block protocol=TCP localport={port}'
            else:
                cmd = f'iptables -A INPUT -p tcp --dport {port} -j DROP'
            
            subprocess.run(cmd, shell=True, check=True)
            
            if port not in self.blocked_ports:
                self.blocked_ports.append(port)
                self.save_blocked_ports()
            
            print(f"{Colors.GREEN}✅ Port {port} blocked successfully{Colors.END}")
            return True
        except Exception as e:
            print(f"{Colors.RED}❌ Failed to block port {port}: {e}{Colors.END}")
            return False
    
    def open_port(self, port):
        """Reopen a previously closed port"""
        if not self.is_admin():
            print(f"{Colors.RED}❌ Administrator privileges required to open ports{Colors.END}")
            return False
        
        try:
            if self.os_type == 'Windows':
                cmd = f'netsh advfirewall firewall delete rule name="PortGuard_Block_{port}"'
            else:
                cmd = f'iptables -D INPUT -p tcp --dport {port} -j DROP'
            
            subprocess.run(cmd, shell=True, check=True)
            
            if port in self.blocked_ports:
                self.blocked_ports.remove(port)
                self.save_blocked_ports()
            
            print(f"{Colors.GREEN}✅ Port {port} opened successfully{Colors.END}")
            return True
        except Exception as e:
            print(f"{Colors.RED}❌ Failed to open port {port}: {e}{Colors.END}")
            return False
    
    def show_port_details(self, port):
        """Show detailed information about a specific port"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}🔍 Port {port} Details{Colors.END}")
        print(f"{Colors.DIM}╭{'─' * 60}╮{Colors.END}")
        
        # Port category
        category = self.get_port_category(port)
        print(f"{Colors.DIM}│{Colors.END} {Colors.WHITE}Category:{Colors.END} {Colors.YELLOW}{category}{Colors.END}")
        
        # Well-known service
        service = WELL_KNOWN_PORTS.get(port)
        if service:
            print(f"{Colors.DIM}│{Colors.END} {Colors.WHITE}Service:{Colors.END} {Colors.GREEN}{service}{Colors.END}")
        else:
            print(f"{Colors.DIM}│{Colors.END} {Colors.WHITE}Service:{Colors.END} {Colors.DIM}Unknown/Unassigned{Colors.END}")
        
        # Check if blocked
        is_blocked = port in self.blocked_ports
        status_color = Colors.RED if is_blocked else Colors.GREEN
        status_text = "BLOCKED" if is_blocked else "OPEN"
        print(f"{Colors.DIM}│{Colors.END} {Colors.WHITE}Status:{Colors.END} {status_color}{status_text}{Colors.END}")
        
        # Try to get process using this port
        try:
            if self.os_type == 'Windows':
                cmd = f'netstat -ano | findstr :{port}'
            else:
                cmd = f'lsof -i :{port}'
            
            output = subprocess.check_output(cmd, shell=True, text=True)
            if output.strip():
                print(f"{Colors.DIM}│{Colors.END} {Colors.WHITE}Active Connections:{Colors.END}")
                for line in output.strip().split('\n')[:5]:
                    print(f"{Colors.DIM}│{Colors.END}   {Colors.DIM}{line[:55]}{Colors.END}")
        except:
            print(f"{Colors.DIM}│{Colors.END} {Colors.DIM}No active connections found{Colors.END}")
        
        print(f"{Colors.DIM}╰{'─' * 60}╯{Colors.END}\n")
    
    def continuous_monitor(self):
        """Continuously monitor ports"""
        print(f"{Colors.CYAN}🔄 Live monitoring mode - Press Ctrl+C to stop{Colors.END}")
        try:
            while self.running:
                results = self.get_active_connections()
                self.display_results(results)
                time.sleep(self.refresh_interval)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}⏹️  Monitoring stopped{Colors.END}")
    
    def interactive_menu(self):
        """Interactive menu for port management"""
        while True:
            self.clear_screen()
            self.print_banner()
            
            print(f"{Colors.BOLD}Main Menu:{Colors.END}\n")
            print(f"{Colors.CYAN}1.{Colors.END} {Colors.WHITE}Quick Scan (Common Ports 1-1024){Colors.END}")
            print(f"{Colors.CYAN}2.{Colors.END} {Colors.WHITE}Full Scan (All Ports){Colors.END}")
            print(f"{Colors.CYAN}3.{Colors.END} {Colors.WHITE}Active Connections{Colors.END}")
            print(f"{Colors.CYAN}4.{Colors.END} {Colors.WHITE}Manage Ports (Close/Open){Colors.END}")
            print(f"{Colors.CYAN}5.{Colors.END} {Colors.WHITE}Live Monitor{Colors.END}")
            print(f"{Colors.CYAN}6.{Colors.END} {Colors.WHITE}Port Details{Colors.END}")
            print(f"{Colors.CYAN}7.{Colors.END} {Colors.WHITE}Blocked Ports List{Colors.END}")
            print(f"{Colors.CYAN}8.{Colors.END} {Colors.RED}Exit{Colors.END}")
            
            choice = input(f"\n{Colors.BOLD}Select option (1-8): {Colors.END}").strip()
            
            if choice == '1':
                results = self.scan_ports(1, 1024, only_active=True)
                self.display_results(results)
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.END}")
            
            elif choice == '2':
                print(f"{Colors.YELLOW}⚠️  Full scan may take several minutes{Colors.END}")
                confirm = input("Continue? (y/n): ").lower()
                if confirm == 'y':
                    results = self.scan_ports(1, 65535, only_active=True)
                    self.display_results(results)
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.END}")
            
            elif choice == '3':
                results = self.get_active_connections()
                self.display_results(results)
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.END}")
            
            elif choice == '4':
                self.manage_ports_menu()
            
            elif choice == '5':
                self.continuous_monitor()
            
            elif choice == '6':
                port = input(f"{Colors.WHITE}Enter port number: {Colors.END}").strip()
                if port.isdigit():
                    self.show_port_details(int(port))
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.END}")
            
            elif choice == '7':
                self.show_blocked_ports()
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.END}")
            
            elif choice == '8':
                print(f"\n{Colors.CYAN}👋 Goodbye!{Colors.END}")
                break
    
    def manage_ports_menu(self):
        """Submenu for managing ports"""
        while True:
            self.clear_screen()
            self.print_banner()
            
            print(f"{Colors.BOLD}Port Management:{Colors.END}\n")
            print(f"{Colors.CYAN}1.{Colors.END} {Colors.RED}Close a Port{Colors.END}")
            print(f"{Colors.CYAN}2.{Colors.END} {Colors.GREEN}Open a Port{Colors.END}")
            print(f"{Colors.CYAN}3.{Colors.END} {Colors.WHITE}Back to Main Menu{Colors.END}")
            
            choice = input(f"\n{Colors.BOLD}Select option (1-3): {Colors.END}").strip()
            
            if choice == '1':
                port = input(f"{Colors.WHITE}Enter port to close: {Colors.END}").strip()
                if port.isdigit():
                    if self.close_port(int(port)):
                        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.END}")
            
            elif choice == '2':
                if self.blocked_ports:
                    print(f"\n{Colors.YELLOW}Currently blocked ports: {self.blocked_ports}{Colors.END}")
                port = input(f"{Colors.WHITE}Enter port to open: {Colors.END}").strip()
                if port.isdigit():
                    if self.open_port(int(port)):
                        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.END}")
            
            elif choice == '3':
                break
    
    def show_blocked_ports(self):
        """Display list of blocked ports"""
        print(f"\n{Colors.BOLD}🚫 Blocked Ports:{Colors.END}")
        if self.blocked_ports:
            for port in self.blocked_ports:
                service = WELL_KNOWN_PORTS.get(port, "Unknown")
                print(f"  {Colors.RED}●{Colors.END} Port {port}: {Colors.DIM}{service}{Colors.END}")
        else:
            print(f"  {Colors.DIM}No ports are currently blocked{Colors.END}")

def main():
    """Main entry point"""
    app = PortGuard()
    
    # Check for command-line arguments
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'scan':
            app.clear_screen()
            app.print_banner()
            results = app.get_active_connections()
            app.display_results(results)
        
        elif command == 'monitor':
            app.continuous_monitor()
        
        elif command == 'close' and len(sys.argv) > 2:
            port = int(sys.argv[2])
            app.close_port(port)
        
        elif command == 'open' and len(sys.argv) > 2:
            port = int(sys.argv[2])
            app.open_port(port)
        
        elif command == 'info' and len(sys.argv) > 2:
            port = int(sys.argv[2])
            app.show_port_details(port)
        
        elif command == 'blocked':
            app.show_blocked_ports()
        
        else:
            print(f"{Colors.YELLOW}Usage: portguard [scan|monitor|close <port>|open <port>|info <port>|blocked]{Colors.END}")
    else:
        # Interactive mode
        app.interactive_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⏹️  Program terminated by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.END}")