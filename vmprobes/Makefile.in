CC := gcc

CFLAGS := -fPIC
CFLAGS += -Wall
CFLAGS += -O2
CFLAGS += -g

# xenaccess
CFLAGS += -D ENABLE_XEN -D XA_DEBUG
XOBJECTS := ../xenaccess/linux_core.o
XOBJECTS += ../xenaccess/linux_domain_info.o
XOBJECTS += ../xenaccess/linux_memory.o
XOBJECTS += ../xenaccess/linux_symbols.o
XOBJECTS += ../xenaccess/windows_core.o
XOBJECTS += ../xenaccess/windows_memory.o
XOBJECTS += ../xenaccess/windows_process.o
XOBJECTS += ../xenaccess/windows_symbols.o
XOBJECTS += ../xenaccess/xa_cache.o
XOBJECTS += ../xenaccess/xa_core.o
XOBJECTS += ../xenaccess/xa_domain_info.o
XOBJECTS += ../xenaccess/xa_error.o
XOBJECTS += ../xenaccess/xa_file.o
XOBJECTS += ../xenaccess/xa_memory.o
XOBJECTS += ../xenaccess/xa_pretty_print.o
XOBJECTS += ../xenaccess/xa_symbols.o
XOBJECTS += ../xenaccess/xa_util.o

# vmprobes
CFLAGS += -D VMPROBE_i386
CFLAGS += -D VMPROBE_SIGNAL
#CFLAGS += -D VMPROBE_BENCHMARK
CFLAGS += -D VMPROBE_DEBUG
OBJECTS += vmprobes.o

# vmprobes examples
LFLAGS := -lxenctrl
LFLAGS += -lxenstore
EXAMPLES := examples/vmprobebio
EXAMPLES += examples/vmprobeopen
EXAMPLES += examples/vmprobenull
EXAMPLES += examples/vmprobegeneric

default: Makefile $(XOBJECTS) $(OBJECTS) $(EXAMPLES)
	@echo "compiling vmprobes (be patient)"
	$(MAKE) $(EXAMPLES)
	@echo "vmprobes compiled"

../xenaccess/%.o: ../xenaccess/%.c
	$(CC) -c $(CFLAGS) -I../ -o $@ $<

%.o: %.c
	$(CC) -c $(CFLAGS) -I../ -o $@ $<

examples/%: examples/%.c $(OBJECTS) $(XOBJECTS)
	$(CC) $(CFLAGS) -I../ -I./ $(LFLAGS) $(OBJECTS) $(XOBJECTS) -o $@ $<

clean:
	$(RM) -f $(OBJECTS)
	$(RM) -f $(EXAMPLES)
	@echo "vmprobes cleaned"

.SECONDARY:
