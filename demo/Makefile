ROOT ?= ..
include $(ROOT)/common.mk

.PHONY: all clean
all: $(ROOT)/demo-agent

$(ROOT)/demo-agent: $(ROOT)/demo/demo-agent.c $(ROOT)/demo/Makefile $(ROOT)/common.mk
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) -l:libssl.so.3 -l:libcrypto.so.3 -o $@

clean:
	$(RM) $(ROOT)/demo-agent
