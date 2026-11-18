ROOT ?= ..
include $(ROOT)/common.mk

.PHONY: all clean
all: $(ROOT)/agent.bpf.o

$(ROOT)/agent.bpf.o: $(ROOT)/bpf/agent.bpf.c $(ROOT)/include/events.h $(ROOT)/bpf/Makefile $(ROOT)/common.mk
	$(CLANG) -target bpf -g -O2 -I$(ROOT)/include $(CPPFLAGS) -c $< -o $@

clean:
	$(RM) $(ROOT)/agent.bpf.o
