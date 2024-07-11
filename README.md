# __Basic Network Sniffer__

**Author**: Sanya Sinha

## Overview

This project is a basic network sniffer implemented in Python. It captures and displays various network packets transmitted over the network. The sniffer is designed to run on Windows and Unix-based systems and provides detailed information about Ethernet and IPv4 packets.

## Features

- Captures Ethernet frames and extracts MAC addresses.
- Parses IPv4 packets and displays header information.
- Identifies common protocols like ICMP, TCP, UDP, and OSPF.
- Enables promiscuous mode to capture all network traffic on the system.

## Requirements

- Python 3.x
- Administrative privileges (to create raw sockets and enable promiscuous mode)
- `sudo` access on Unix-based systems (to enable promiscuous mode)

## Usage

### Running the Script

1. Open a command prompt or terminal.
2. Navigate to the project directory.
3. Run the script with administrative privileges:
    - On Windows:
        ```sh
        python network_sniffer.py
        ```
    - On Unix-based systems:
        ```sh
        sudo python3 network_sniffer.py
        ```

### Script Output

The script outputs information about captured Ethernet and IPv4 packets in the following format:

