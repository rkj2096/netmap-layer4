#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <iostream>
  
#define PORT    8080 
#define MAXLINE 65536

using namespace std;


unsigned short checksum(unsigned short* buff, int _16bitword){
	unsigned long sum;
	for(sum=0;_16bitword>0;_16bitword--)
	sum+=htons(*(buff)++);
	sum = ((sum >> 16) + (sum & 0xFFFF));
	sum += (sum>>16);
	return (unsigned short)(~sum);
}



int main() { 
    int sockfd; 
    struct sockaddr cliaddr;
    int addrlen = sizeof(cliaddr), n;
    char buffer[MAXLINE]; 
    struct ether_header *eh; 
    struct ip *ip;
    struct udphdr *udp;
      
    if((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
       
    while(1){
		if((n = recvfrom(sockfd, buffer, MAXLINE, 0, &cliaddr,(socklen_t *)&addrlen)) < 0 ){ 
			perror("recv failed"); 
			exit(EXIT_FAILURE); 
		} 
		buffer[n] = '\0';
		
		eh = (struct ether_header *)(buffer);
		ip = (struct ip *)(buffer + sizeof(*eh));
		udp = (struct udphdr *)(buffer + sizeof(*eh) + sizeof(*ip));
		char *body = (char *)(buffer + sizeof(*eh) + sizeof(*ip));
		
		if(ip->ip_dst.s_addr == ip->ip_src.s_addr)
		cout<<ip->ip_dst.s_addr<<endl;
		cout<<ip->ip_src.s_addr<<endl;
		cout<<udp->uh_sport<<endl;
		cout<<udp->uh_dport<<endl;
		
		if(htons(PORT) != udp->uh_sport)
			continue;
		
		cout<<body<<endl;
		
		uint16_t temp = udp->uh_sport;
		udp->uh_sport = udp->uh_dport;
		udp->uh_dport = temp;
		
		if(sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *)&cliaddr, addrlen) < 0)
		{
			perror("send failed"); 
			//exit(EXIT_FAILURE); 
		}
	}
      
    return 0; 
} 
