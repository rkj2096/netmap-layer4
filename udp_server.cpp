#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 
#include <iostream>

#define PORT    8080
#define MAXLINE 1024

using namespace std;

int main() { 
    int sockfd, n; 
    struct sockaddr_in servaddr, cliaddr;
    char buffer[MAXLINE];  

    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 

    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 

    servaddr.sin_family    = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(PORT); 

    if(bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0 ){ 
        perror("bind failed"); 	
        exit(EXIT_FAILURE); 
    } 
      
    while(1){
		memset(buffer, 0, MAXLINE);
		socklen_t* len;
		n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, ( struct sockaddr *) &cliaddr, len); 
		buffer[n] = '\0'; 
		
		cout<<buffer<<endl;
		sendto(sockfd, (const char *)buffer, strlen(buffer), MSG_CONFIRM, (const struct sockaddr *) &cliaddr, *len);
	}  
      
    return 0; 
} 
