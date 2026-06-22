# PortsManager - CLI Port Scanner & Manager

A small modern command-line tool for scanning, monitoring, and managing network ports.

## Features

- Port scanning across all ranges (1-65535)
- Well-known service identification (HTTP, SSH, MySQL, Redis, etc.)
- Organized output by port categories (well-known, registered, dynamic)
- Close and reopen ports via native firewall integration
- Real-time connection monitoring
- Both interactive menu and direct command-line modes
- Cross-platform support (Windows, Linux, macOS)

## Requirements

- Python 3.6+
- Administrator/sudo privileges required for port management
- No external dependencies

## Installation

```bash
git clone https://github.com/DangerousAngel/portsManager.git
cd portguard
python portsManager.py
