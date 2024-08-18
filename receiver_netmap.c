#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <ifaddrs.h>    /* getifaddrs */
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <net/netmap_user.h>

#include <assert.h>
#include <math.h>

#define MAX_BODYSIZE  65536
#define VIRT_HDR_1    10  /* length of a base vnet-hdr */
#define VIRT_HDR_2    12  /* length of the extended vnet-hdr */
#define VIRT_HDR_MAX  VIRT_HDR_2

// IP and MAC addresses
char sender_ip[20] = "127.0.0.1:8080";
char recv_ip[20]   = "10.16.32.162:8081";
char sender_mac[20] = "40:b0:34:9b:6c:9e";
char recv_mac[20]   = "ff:ff:ff:ff:ff:ff";  // Broadcast MAC address

// IP and port information in network byte order
uint32_t sender_uip, recv_uip;
uint16_t sender_port, recv_port;

// Virtual header structure (if needed)
struct virt_header {
    uint8_t fields[VIRT_HDR_MAX];
};

// Packet structure (Ethernet + IPv4 + UDP + Payload)
struct pkt {
    // struct virt_header vh; 
    struct ether_header eh; 
    struct {
        struct ip ip; 
        struct udphdr udp; 
        uint8_t body[MAX_BODYSIZE]; /* Hardwired payload size */
    } ipv4;
};

// Function to extract IPv4 address and port from a string (e.g., "127.0.0.1:8080")
static void extract_ipv4_addr(char *name, uint32_t *addr, uint16_t *port) {
    struct in_addr a;
    char *pp;

    pp = strchr(name, ':');  // Find the colon separating IP and port
    if (pp != NULL) {  // If a port is specified
        *pp++ = '\0'; 
        *port = (uint16_t)strtol(pp, NULL, 0); 
    }
    printf("%s\n", pp);  
    inet_pton(AF_INET, name, &a);  // Convert IP to network byte order
    *addr = ntohl(a.s_addr);  // Convert to host byte order
}

/* Compute the checksum of the given IP header */
static uint32_t checksum(const void *data, uint16_t len, uint32_t sum) {
    const uint8_t *addr = data;
    uint32_t i;

    /* Checksum all the pairs of bytes first */
    for (i = 0; i < (len & ~1U); i += 2) {
        sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    /* If there's a single byte left over, checksum it too */
    if (i < len) {
        sum += addr[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    return sum;
}

/* Wrap the checksum into 16 bits */
static uint16_t wrapsum(uint32_t sum) {
    sum = ~sum & 0xFFFF;
    return (htons(sum));
}

/* Process the packet, extracting and printing some fields */
void process_packet(char* packet) {
    struct pkt *pkt = (struct pkt*)packet;
    printf("%s\n", ether_ntoa((struct ether_addr *)pkt->eh.ether_shost));  
    printf("%s\n", pkt->ipv4.body);
}

int main(int argc, char **argv) {
    struct netmap_if *nifp;
    struct netmap_ring *ring;
    struct nmreq nmr;
    struct pollfd fds;
    int i, fd = 0;
    void *p = NULL;
    void *buf = NULL;
    int tot = 0;
    int nret = 0;

    if (argc < 2) {
        printf("%s int\n", argv[0]); 
        return(1);
    }

    if ((fd = open("/dev/netmap", O_RDWR)) < 0) {  // Open the Netmap device
        perror("open");
        return(1);
    }
    printf("fd %d\n", fd);
   
    bzero(&nmr, sizeof(nmr));
    strcpy(nmr.nr_name, argv[1]);  // Use the interface name provided as argument
    nmr.nr_version  = NETMAP_API;  // Set the Netmap API version

    /* Register interface for Netmap mode, bypass OS stack */
    if (ioctl(fd, NIOCREGIF, &nmr) != 0) {
        printf("%d %s\n", errno, strerror(errno));
        perror("ioctl hello");
        return(1);
    }
    /* Map kernel ring buffers to userspace */
    if ((p = mmap(0, nmr.nr_memsize, PROT_READ | PROT_WRITE, MAP_SHARED , fd, 0)) == MAP_FAILED) {  // Corrected NULL check to MAP_FAILED
        perror("mmap");
        return(1);
    }
    nifp =  NETMAP_IF(p, nmr.nr_offset);  // Get the Netmap interface structure
    ring =  NETMAP_RXRING(nifp, 0);  // Get the first receive ring
    fds.fd  = fd;
    fds.events = POLLIN;
    for (;;) {
        poll(&fds, 1, 1000);  // Poll the Netmap file descriptor
        while (!nm_ring_empty(ring)) {  // Check if there are packets in the ring
            i = ring->cur;
            buf = NETMAP_BUF(ring,  ring->slot[i].buf_idx);  // Get the buffer containing the packet

            /* Insert your cool stuff here */
            process_packet(buf);  // Process the packet

            ring->head = ring->cur  = nm_ring_next(ring, i);  // Move to the next slot
            nret++;
        }
        if (ioctl(fd, NIOCRXSYNC, NULL) != 0)  // Sync with the kernel to update the ring
            perror("sync ioctl");
        tot += nret;
        printf("recv'd %d packets, total: %d\n", nret, tot);  // Print the number of packets received
        nret = 0;
    }
    return 0;
}
