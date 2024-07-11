# __Basic Network Sniffer__

**Author**: Sanya Sinha

## Overview

This project is a basic network sniffer implemented in Python. It captures and displays various network packets transmitted over the network. The sniffer is designed to run on Windows and Unix-based systems and provides detailed information about Ethernet and IPv4 packets.

## Functions

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
        python Basic_Network_Sniffer.py
        ```
    - On Unix-based systems:
        ```sh
        sudo Basic_Network_Sniffer.py
        ```

### Script Output

The script outputs information about captured Ethernet and IPv4 packets in the following format:
![Screenshot 2024-07-11 183121](https://github.com/SanyaSinha11/CodeAlpha-Basic_Network_Sniffer/assets/124815376/b3ae68cd-bb8b-415d-8394-f24356d4d238)

### Stopping the Sniffer

To stop the packet capturing, press `Ctrl + C`.

## Code Explanation

### Libraries Used

1. **socket**:
    - Provides access to the BSD socket interface. This is used to create raw sockets and manage network connections.
    
2. **struct**:
    - Provides functionality for working with C-style data structures. This is used to unpack binary data from network packets.
    
3. **os**:
    - Provides a way of using operating system-dependent functionality. This is used to check the operating system and enable promiscuous mode on Unix-based systems.
    
4. **subprocess**:
    - Allows you to spawn new processes, connect to their input/output/error pipes, and obtain their return codes. This is used to enable promiscuous mode on Unix-based systems.

### Main Functions

1. **raw_socket()**:
    - Creates a raw socket to capture all packets.
    - Returns the socket object.

2. **bind_socket(network_sniff)**:
    - Binds the socket to the default network interface (0.0.0.0).
    - Allows the sniffer to capture all network traffic on the system.

3. **config_socket(network_sniff)**:
    - Configures the socket to include IP headers in captured packets.
    - Enables promiscuous mode for capturing all traffic on the system.

4. **extrct_ethFrame(data)**:
    - Extracts MAC addresses and protocol type from the Ethernet frame.
    - Returns destination MAC, source MAC, protocol, and remaining data.

5. **format_mac(bytes_addr)**:
    - Converts MAC addresses from binary to human-readable format.

6. **extrct_ipPacket(data)**:
    - Extracts header fields from IPv4 packet.
    - Returns version, header length, TTL, protocol, source IP, destination IP, and remaining data.

7. **ipv4(addr)**:
    - Converts binary IP addresses to human-readable string.

8. **cap_pckts(network_sniff)**:
    - Captures and displays packets in a continuous loop.
    - Parses and prints Ethernet and IPv4 packet details.

9. **main()**:
    - Initializes and configures the socket.
    - Starts packet capturing.

### Protocol Mapping

The script uses a dictionary to map protocol numbers to names:
```python
prtcl_map = {
    1 : "ICMP",
    6 : "TCP",
    17 : "UDP",
    89 : "OSPF",
}
```

### Promiscuous Mode

- **Windows**:
    - Uses `SIO_RCVALL` to enable promiscuous mode.
- **Unix-based systems**:
    - Uses `ip link set [interface] promisc on` command to enable promiscuous mode.

## Troubleshooting

### Common Issues

- **Socket Error**:
    - Ensure the script is run with administrative privileges.
    - Check if the antivirus or firewall is blocking raw socket creation.

- **Promiscuous Mode Not Enabled**:
    - On Windows, verify if the socket library supports `SIO_RCVALL`.
    - On Unix-based systems, ensure `sudo` access is available.

## Support

For any issues or questions, please open an issue on the GitHub repository or contact the author. 


