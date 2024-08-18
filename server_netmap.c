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



char sender_ip[20] = "192.168.43.12";
char recv_ip[20]   = "192.168.43.12";
char sender_mac[20] = "3c:a0:67:ed:2a:29";
char recv_mac[20]   = "3c:a0:67:ed:2a:29";

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

void prepare_packet(char *payload, char *buf, int *len){

    struct pkt *pkt;
    struct ether_header *eh;
    struct ip ip;
    struct udphdr udp;

    uint16_t paylen = strlen(payload);
    pkt = malloc(sizeof(struct pkt));

    /* prepare the headers */
    eh = &pkt->eh;
    bcopy(ether_aton(sender_mac), eh->ether_shost, 6);//
    bcopy(ether_aton(recv_mac), eh->ether_dhost, 6);//

    eh->ether_type = htons(ETHERTYPE_IP);
    memcpy(&ip, &pkt->ipv4.ip, sizeof(ip));
    ip.ip_v = IPVERSION;
    ip.ip_hl = sizeof(ip) >> 2;
    ip.ip_id = 0;
    ip.ip_tos = IPTOS_LOWDELAY;
    ip.ip_len = htons(60 - sizeof(*eh));//
    ip.ip_id = 0;
    ip.ip_off = htons(IP_DF); /* Don't fragment */
    ip.ip_ttl = IPDEFTTL;
    ip.ip_p = IPPROTO_UDP;
    ip.ip_dst.s_addr = htonl(recv_uip);//
    ip.ip_src.s_addr = htonl(recv_uip);//
    ip.ip_sum = wrapsum(checksum(&ip, sizeof(ip), 0));
    memcpy(&pkt->ipv4.ip, &ip, sizeof(ip));

    memcpy(&udp, &pkt->ipv4.udp, sizeof(udp));
    udp.uh_sport = htons(sender_port);//
    udp.uh_dport = htons(recv_port);//
    udp.uh_ulen = htons(paylen);//

    /* Magic: taken from sbin/dhclient/packet.c */
    udp.uh_sum = wrapsum(
        checksum(&udp, sizeof(udp), /* udp header */
        checksum(pkt->ipv4.body,    /* udp payload */
        paylen,
        checksum(&pkt->ipv4.ip.ip_src, /* pseudo header */
        2 * sizeof(pkt->ipv4.ip.ip_src),
        IPPROTO_UDP + (u_int32_t)ntohs(udp.uh_ulen)))));
    memcpy(&pkt->ipv4.udp, &udp, sizeof(udp));

    *len = sizeof(*eh) + sizeof(ip) + sizeof(udp) + paylen;

    memcpy((pkt->ipv4.body), payload, sizeof(uint8_t) * paylen); //check

    memcpy(buf, pkt, *len);
}

void process_packet(char* packet){
    struct pkt *pkt = (struct pkt*)packet;
    printf("%s\n", ether_ntoa(pkt->eh.ether_shost));

}

int
main(int argc, char **argv)
{
    struct netmap_if *nifp;
    struct netmap_ring *ring;
    struct nmreq nmr;
    struct pollfd fds;
    void *p;
    char *buf;
    int i, fd, len;

    if (argc < 2) {
        printf("%s Interface\n", argv[0]); 
        return(1);
    }

    extract_ipv4_addr(sender_ip, &sender_uip, &sender_port);
    extract_ipv4_addr(recv_ip, &recv_uip, &recv_port);

    if ((fd = open("/dev/netmap", O_RDWR)) < 0) {
        perror("open");
        return(1);
    }

    bzero(&nmr, sizeof(nmr));
    strcpy(nmr.nr_name, argv[1]);
    nmr.nr_version = NETMAP_API;

    /* Register interface for Netmap mode, bypass OS stack */
    ioctl(fd, NIOCREGIF, &nmr);

    /* MAP kernerl ring buffers to userspace */
    if ((p = mmap(0, nmr.nr_memsize, PROT_READ | PROT_WRITE, MAP_SHARED , fd, 0)) == NULL) {
        perror("mmap");
        return(1);
    }

    nifp = NETMAP_IF(p, nmr.nr_offset);
    ring = NETMAP_TXRING(nifp, 0);
    fds.fd = fd;
    fds.events = POLLOUT;
    for (;;) {
        poll(&fds, 1, -1);
        while (!nm_ring_empty(ring)) {
            i = ring->cur;
            buf = NETMAP_BUF(ring, ring->slot[i].buf_idx);
            //... prepare packet in buf ...
            printf("Sending packet\n");
            prepare_packet("one packet", buf, &len);
            ring->slot[i].len = len;
            ring->head = ring->cur = nm_ring_next(ring, i);
        }
    }
}
