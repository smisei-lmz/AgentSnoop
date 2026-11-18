.PHONY: all bpf user demo agent.bpf.o agentsnoop demo-agent test clean
all: bpf user demo

bpf: agent.bpf.o
user: agentsnoop
demo: demo-agent

agent.bpf.o:
	$(MAKE) -f bpf/Makefile ROOT=. all

agentsnoop:
	$(MAKE) -f user/Makefile ROOT=. all

demo-agent:
	$(MAKE) -f demo/Makefile ROOT=. all

test: all
	python3 demo/demo.py

clean:
	$(MAKE) -C bpf clean
	$(MAKE) -C user clean
	$(MAKE) -C demo clean
