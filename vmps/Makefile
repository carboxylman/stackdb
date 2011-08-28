CC := gcc

CFLAGS := -fPIC
CFLAGS += -Wall
CFLAGS += -O2
#CFLAGS += -g
CFLAGS += -I./

# xenaccess
CFLAGS += -D ENABLE_XEN
OBJECTS := xenaccess/linux_core.o
OBJECTS += xenaccess/linux_domain_info.o
OBJECTS += xenaccess/linux_memory.o
OBJECTS += xenaccess/linux_symbols.o
OBJECTS += xenaccess/windows_core.o
OBJECTS += xenaccess/windows_memory.o
OBJECTS += xenaccess/windows_process.o
OBJECTS += xenaccess/windows_symbols.o
OBJECTS += xenaccess/xa_cache.o
OBJECTS += xenaccess/xa_core.o
OBJECTS += xenaccess/xa_domain_info.o
OBJECTS += xenaccess/xa_error.o
OBJECTS += xenaccess/xa_file.o
OBJECTS += xenaccess/xa_memory.o
OBJECTS += xenaccess/xa_pretty_print.o
OBJECTS += xenaccess/xa_symbols.o
OBJECTS += xenaccess/xa_util.o

# process-list
LFLAGS := -lxenctrl
LFLAGS += -lxenstore
LFLAGS += -lebl
LFLAGS += -lelf
LFLAGS += -ldw
OBJECTS += offset.o
OBJECTS += report.o
OBJECTS += process-list.o
TARGET := process-list

default:
	@echo "compiling process-list (be patient)"
	@$(MAKE) $(TARGET)
	@echo "process-list compiled"

%.o: %.c
	@$(CC) -c $(CFLAGS) -o $@ $<

$(TARGET): $(OBJECTS)
	@$(CC) $(CFLAGS) $(OBJECTS) $(LFLAGS) -o $@

clean:
	@$(RM) -f $(OBJECTS)
	@$(RM) -f $(TARGET)
	@echo "process-list cleaned"

run:
	sudo ./$(TARGET) --report a3-app
