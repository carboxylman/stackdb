LIBS= -lelf -ldw -lebl -lxenaccess -lxenctrl
CFLAGS= -Wall -g -O2 -DHAVE_CONFIG_H 
ARGS= a3guest /boot/vmlinux-syms-2.6.18.8-xenU 

all: process_list

process_list: process_list.c
	$(CC) $(CFLAGS) process-list.c -o process-list $(LIBS)

run:
	sudo ./process-list $(ARGS)

clean:
	rm -f process-list
