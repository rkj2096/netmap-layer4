#include <cstdlib>
#include <vector>
#include <cstring>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fstream>
#include <bits/socket.h>
#include <string>
#include <errno.h>
#include <signal.h>
#include <wait.h>
#include <pthread.h>
#include <iostream>

#define PORT    8080 
#define MAXLINE 1024 

using namespace std;

int *reqs;
double *response_time;
bool done = false;
struct sockaddr_in servaddr;

int create_socket(){
	int sockfd;
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ){ 
        perror("socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
    return sockfd;
}


void* loadgen_func(void* arg){
    int id = *(int*)arg, sockfd, i=0, n;
    socklen_t* len;
    time_t start_time;
    char buffer[MAXLINE];
    
    sockfd = create_socket();
    while(1){
        if(done) break;
        
        start_time = time(NULL);
        
        sendto(sockfd, "12", 2, MSG_CONFIRM, (const struct sockaddr *) &servaddr, sizeof(servaddr));
        n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &servaddr, len);
        cout<<buffer<<endl;
        response_time[id] += difftime(time(NULL), start_time);
        reqs[id]++;
        cout<<buffer<<endl;
    }
    //time-out
    close(sockfd);
    reqs[id]++;
}

  
int main(int argc, char** argv) { 
    if(argc < 3){
        cout<<"Too less args"<<endl;
        exit(0);
    }
    int no_threads = atoi(argv[1]);
    int ids[no_threads], i;
    pthread_t cli_thread[no_threads];
    
    reqs = (int*)malloc(no_threads * sizeof(int));
    response_time = (double*)malloc(no_threads * sizeof(double));
    memset(&servaddr, 0, sizeof(servaddr)); 
      
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(PORT); 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
	
	//create worker thread
    for(i = 0; i < no_threads; i++){
        ids[i] = i;
        pthread_create(cli_thread + i, NULL, loadgen_func, (void *)(ids + i));
    }
	
	int time = atoi(argv[2]);
    sleep(time);
    done = true; //time-out
    
    for(i = 0; i < no_threads; i++)
        pthread_join(cli_thread[i], NULL);
    
    int total_req = 0; 
    double total_response_time = 0;
    for(i=0; i<no_threads; i++){
        total_req += reqs[i];
        total_response_time += response_time[i];
    }

	cout<<no_threads<<","<<(double)total_req/time<<","<<total_response_time/total_req<<endl;
    
    free(reqs);
    free(response_time);
    return 0;
} 
