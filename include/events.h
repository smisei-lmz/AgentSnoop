#pragma once
#include <linux/types.h>

enum kind { OPEN = 1, EXEC, CONNECT, WRITE, TLS_OUT, TLS_IN };
enum { PATH_BYTES = 256, FRAMES = 24 };
struct event {
    __u64 ns;
    __u32 agent, pid, tid, kind;
    __s64 result;
    __u32 flags, ip;
    __u16 port;
    char text[PATH_BYTES];
};
struct root { __u64 start_ticks, ns_per_tick; };
struct site { __u32 agent; __s32 stack; };
struct allocation { struct site site; __u64 bytes; };
enum counter { RING_DROP, MAP_DROP, STACK_FAIL, ALLOCS, FREES, COUNTERS };
