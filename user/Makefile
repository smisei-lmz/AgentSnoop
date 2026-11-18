ROOT ?= ..
include $(ROOT)/common.mk

SOURCES := $(addprefix $(ROOT)/user/,monitor.c rules.c stacks.c tls.c)
HEADERS := $(ROOT)/user/monitor.h $(ROOT)/include/events.h

.PHONY: all clean
all: $(ROOT)/agentsnoop

$(ROOT)/agentsnoop: $(SOURCES) $(HEADERS) $(ROOT)/user/Makefile $(ROOT)/common.mk
	$(CC) -I$(ROOT)/include $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) -lbpf -lelf -lz -ldl -o $@

clean:
	$(RM) $(ROOT)/agentsnoop
