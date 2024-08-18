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

#define VIRT_HDR_1  10  /* length of a base vnet-hdr */
#define VIRT_HDR_2  12  /* length of the extenede vnet-hdr */
#define VIRT_HDR_MAX    VIRT_HDR_2



char sender_ip[20] = "127.0.0.1:8080";
char recv_ip[20]   = "10.16.32.162:8081";
char sender_mac[20] = "40:b0:34:9b:6c:9e";
//char recv_mac[20]   = "40:b0:34:9b:6c:9e";
char recv_mac[20]   = "ff:ff:ff:ff:ff:ff";

uint32_t sender_uip, recv_uip;
uint16_t sender_port, recv_port;

struct virt_header {
    uint8_t fields[VIRT_HDR_MAX];
};

struct pkt {
    //struct virt_header vh;
    struct ether_header eh;
    struct {
        struct ip ip;
        struct udphdr udp;
        uint8_t body[MAX_BODYSIZE]; /* hardwired */
    } ipv4;
} ;


static void
extract_ipv4_addr(char *name, uint32_t *addr, uint16_t *port)
{
    struct in_addr a;
    char *pp;

    pp = strchr(name, ':');
    if (pp != NULL) {   /* do we have ports ? */
        *pp++ = '\0';
        *port = (uint16_t)strtol(pp, NULL, 0);
    }
    printf("%s\n", pp);
    inet_pton(AF_INET, name, &a);
    *addr = ntohl(a.s_addr);
}


/* Compute the checksum of the given ip header. */
static uint32_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
    const uint8_t *addr = data;
    uint32_t i;

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (len & ~1U); i += 2) {
        sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < len) {
        sum += addr[i] << 8;
        if (sum > 0xFFFF)
            sum -= 0xFFFF;
    }
    return sum;
}

static uint16_t
wrapsum(uint32_t sum)
{
    sum = ~sum & 0xFFFF;
    return (htons(sum));
}

void process_packet(char* packet){
    struct pkt *pkt = (struct pkt*)packet;
    printf("%s\n", ether_ntoa(pkt->eh.ether_shost));

    printf("%s\n", pkt->ipv4.body);
}

int
main(int argc, char **argv)
{
        struct  netmap_if *nifp;
        struct  netmap_ring *ring;
        struct  nmreq nmr;
        struct  pollfd fds;
        int i, fd = 0;
        void *p = NULL;
        void *buf = NULL;
        int tot = 0;
        int nret = 0;

        if (argc < 2) {
                printf("%s int\n", argv[0]); 
                return(1);
        }

        if ((fd = open("/dev/netmap", O_RDWR)) < 0) {

                perror("open");
                return(1);

        }printf("fd %d\n", fd);
       
        bzero(&nmr, sizeof(nmr));
        strcpy(nmr.nr_name, argv[1]);
        nmr.nr_version  = NETMAP_API;

        /* Register interface for Netmap mode, bypass OS stack */
        if (ioctl(fd, NIOCREGIF, &nmr) != 0) {
                printf("%d %s\n", errno, strerror(errno));
                perror("ioctl hello");
                return(1);
        }
        /* MAP kernerl ring buffers to userspace */
        if ((p = mmap(0, nmr.nr_memsize, PROT_READ | PROT_WRITE, MAP_SHARED , fd, 0)) == NULL) {
                perror("mmap");
                return(1);
        }
        nifp =  NETMAP_IF(p, nmr.nr_offset);
        ring =  NETMAP_RXRING(nifp, 0);
        fds.fd  = fd;
        fds.events = POLLIN;
        for (;;) {
                poll(&fds, 1, 1000);
                while (!nm_ring_empty(ring)) {
                        i = ring->cur;
                        buf = NETMAP_BUF(ring,  ring->slot[i].buf_idx);
                        /* Insert your cool stuff here */

                        process_packet(buf);

                        ring->head = ring->cur  = nm_ring_next(ring, i);
                        nret++;

                }
                if (ioctl(fd, NIOCRXSYNC, NULL) != 0)
                        perror("sync ioctl");
                tot += nret;
                printf("recv'd %d packets, total: %d\n", nret, tot);
                nret = 0;
        }
        return 0;
}