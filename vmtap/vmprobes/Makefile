CC:= gcc
AR:= ar

CFLAGS:= -fPIC
CFLAGS+= -Wall
CFLAGS+= -O2
#CFLAGS+= -g
CFLAGS+= -D VMPROBE_i386
CFLAGS+= -I../xenaccess/

OBJECTS:= vmprobes.o

TARGET:= libvmprobes.a

default: $(TARGET)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

$(TARGET): $(OBJECTS)
	$(AR) rcs $@ $<
	@echo "vmprobes compiled"

clean:
	rm -f $(OBJECTS) $(TARGET)
	@echo "vmprobes cleaned"
