#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BACKLOG 10

/*
 * Note: We watch global valuable here.
 *       If you want to watch local valuable, 
 *       then you should specify its function name.
 */
int s_pingpong = 0;

int main(int argc, char *argv[]) {
    int connfd, sockfd;
    struct sockaddr_in servaddr;
    struct sockaddr_in tempaddr;
    struct sockaddr_in cliaddr;
    socklen_t clilen;
    char ip_str[INET_ADDRSTRLEN];
    int ret_val;

    socklen_t templen;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        exit(1);
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(10000);

    ret_val =
        bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if (ret_val == -1) {
        perror("bind");
        exit(1);
    }
    printf("the sockfd is %d\n", sockfd);
    ret_val = listen(sockfd, BACKLOG);
    if (ret_val == -1) {
        perror("listen");
        exit(1);
    }

    templen = sizeof(struct sockaddr);
    ret_val = getsockname(sockfd, (struct sockaddr *) &tempaddr, &templen);
    if (ret_val == -1) {
        perror("getsockname");
        exit(1);
    }

    printf("Server is listening on port %d \n", ntohs(tempaddr.sin_port));
    char recv_buffer[32] = "";
    char send_buffer[32] = "";

    for (;;) {
        clilen = sizeof(cliaddr);
        connfd = accept(sockfd, (struct sockaddr *) &cliaddr, &clilen);
        if (connfd == -1) {
            perror("accept");
            continue;
        }
        printf("Server: client %s connect\n", inet_ntoa(cliaddr.sin_addr));

        sleep(8);
        while (1) {
            recv(connfd, recv_buffer, 32, 0);
            sleep(1);
            printf("server received a c_pingpong == %s\n",
                   recv_buffer);

            s_pingpong = atoi(recv_buffer) + 1;

            sleep(4);
            sprintf(send_buffer, "%d", s_pingpong);
            send(connfd, send_buffer, 32, 0);
            printf("server send a s_pingpong == %s\n", send_buffer);
            sleep(5);

        }
        close(connfd);
    }
    return 0;
}
