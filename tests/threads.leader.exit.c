#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

#include <stdio.h>
#include <inttypes.h>

#include <stdlib.h>
#include <stddef.h>
#include <signal.h>
#include <string.h>

#include <sys/types.h>
#include <pthread.h>

pid_t gettid() {
    return syscall(SYS_gettid);
}

void sigh(int signo) {
    printf("pid %d tid %d caught signal %d\n",getpid(),gettid(),signo);
    return; //exit(1);
}

void *looper(void *ticks) {
    volatile int i = (int)ticks;
    while (i) {
	sleep(1);
	printf("thread %d slept %d\n",gettid(),(int)ticks - i);
	--i;
    }
    return NULL;
}

int main(int argc,char **argv) {
    const volatile int j;
    pthread_t pthread_id;

    signal(SIGTRAP,sigh);
    signal(SIGUSR1,sigh);

    pthread_create(&pthread_id,NULL,looper,16);
    sleep(2);
    pthread_create(&pthread_id,NULL,looper,32);
    //looper(&argc);

    sleep(4);

    return 0;
}
