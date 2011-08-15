CC= gcc
LD= ld
CFLAGS= -I/usr/include/python2.5
LFLAGS= -lvmprobes -lxenaccess -lxenctrl

SWIG= swig
SFLAGS= -python

TARGET= vmtap

PY= python

all: vmtap

vmtap: $(TARGET).i $(TARGET).c $(TARGET).h
	$(SWIG) $(SFLAGS) $(TARGET).i
	$(CC) -c $(TARGET).c $(TARGET)_wrap.c $(CFLAGS)
	$(LD) -shared $(TARGET).o $(TARGET)_wrap.o $(LFLAGS) -o _$(TARGET).so

clean:
	rm -f *.o
	rm -f *_wrap.c
	rm -f *.pyc
	rm -f _$(TARGET).so
	rm -f $(TARGET).py

test: test.py
	sudo $(PY) test.py
