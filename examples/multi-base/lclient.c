#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/*
 * Note: We watch global valuable here.
 *       If you want to watch local valuable, 
 *       then you should specify its function name.
 */
int vm9_c_pingpong = 0;

int main(int argc, char *argv[]) {
    int sockfd;
    int conn_ret;
    struct sockaddr_in servaddr;

    if(argc < 3){
        printf("Usage: ./lclient <ip addr> <port>\n");
        exit(0);
    }
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("sock");
        exit(1);
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &servaddr.sin_addr);
    conn_ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if (conn_ret == -1) {
        perror("connect");
    }
    char send_buffer[32] = "";
    char recv_buffer[32] = "";

    if (conn_ret == 0) {
        sleep(8);
        printf("client send c_pingpong = %d\n", vm9_c_pingpong);
        sprintf(send_buffer, "%d", vm9_c_pingpong);
        send(sockfd, send_buffer, 32, 0);
        while (1) {
            recv(sockfd, recv_buffer, 32, 0);
            sleep(1);
            printf("client received s_pingpong == %s\n", recv_buffer);
            vm9_c_pingpong = atoi(recv_buffer) + 1;
            sleep(4);

            sprintf(send_buffer, "%d", vm9_c_pingpong);
            send(sockfd, send_buffer, 32, 0);
            printf("client send c_pingpong = %s\n", send_buffer);
            sleep(5);
        }
    }
    close(sockfd);
    return 0;
}
