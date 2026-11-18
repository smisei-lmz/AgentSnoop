CLANG ?= clang
TARGET_TRIPLE := $(shell $(CC) -dumpmachine)
CPPFLAGS += -I/usr/include/$(TARGET_TRIPLE)
ifneq ($(wildcard $(ROOT)/.deps/include),)
CPPFLAGS += -I$(ROOT)/.deps/include -I$(ROOT)/.deps/include/$(TARGET_TRIPLE)
LDFLAGS += -L$(ROOT)/.deps/lib
endif
CFLAGS += -O2 -g -Wall -Wextra
