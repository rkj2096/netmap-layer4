# netmap

## Overview
A basic packet processing application that uses the Netmap framework to bypass the OS networking stack and interact directly with network interface card (NIC) ring buffers. The program constructs packets containing a custom payload and transmits them over a specified network interface.

## Prerequisites

### System Requirements
- A Linux-based operating system (e.g., Ubuntu, Debian, CentOS).
- Root or sudo access is required to run the program because it directly interfaces with the network hardware.

### Dependencies
- **Netmap**: The Netmap framework must be installed on your system. Netmap is a high-performance packet processing framework for fast packet I/O.

### Install Required Packages

You need to install the following development packages:

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev linux-headers-$(uname -r)
```

### Building Netmap

1. Clone the Netmap repository:
    ```bash
    git clone https://github.com/luigirizzo/netmap.git
    cd netmap
    ```

2. Build and install Netmap:
    ```bash
    ./configure
    make
    sudo make install
    ```

3. Load the Netmap kernel module:
    ```bash
    sudo insmod netmap.ko
    ```

4. Verify that Netmap is working:
    ```bash
    sudo ./examples/pkt-gen -i eth0 -f tx
    ```
    Replace `eth0` with your network interface name.

## Program Compilation

To compile the packet generation program, follow these steps:

1. Save the provided code to a file named `netmap_packet_gen.c`.
2. Compile the program using `gcc`:
    ```bash
    gcc -o netmap_packet_gen netmap_packet_gen.c -lnetmap -lpthread
    ```

## Running the Program

To run the packet generation program, execute the following command:

```bash
sudo ./netmap_packet_gen <interface>
```

### Parameters:

- `<interface>`: Replace this with the name of the network interface you want to send packets through (e.g., `eth0`).

### Example:

```bash
sudo ./netmap_packet_gen eth0
```

## How It Works

- **IP and MAC Address Configuration**: The program uses hardcoded source and destination IP/MAC addresses and ports. These values are set in the global variables:
    - `sender_ip`, `recv_ip`: IP addresses of the sender and receiver.
    - `sender_mac`, `recv_mac`: MAC addresses of the sender and receiver.
    - `sender_port`, `recv_port`: UDP ports of the sender and receiver.

- **Packet Construction**: The `prepare_packet()` function creates an Ethernet frame with an IP and UDP header and adds a custom payload.

- **Packet Transmission**: The program maps the Netmap ring buffers to userspace and enters a loop to continuously send packets.

## Notes

- **Root Access**: The program requires root privileges to run because it directly interfaces with the network hardware.
- **Netmap Device**: The program opens the Netmap device (`/dev/netmap`) to interact with the network interface in Netmap mode.

## Troubleshooting

- **Permission Denied**: If you encounter a "Permission Denied" error, ensure that you are running the program with `sudo`.
- **Netmap Module Not Found**: Ensure that the Netmap kernel module is loaded by running `sudo insmod netmap.ko`.
- **Interface Not Found**: Ensure that the specified network interface exists and is active.

## References

- The Netmap framework (https://github.com/luigirizzo/netmap) for high-performance packet processing.
