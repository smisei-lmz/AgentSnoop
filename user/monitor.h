#pragma once
#include "events.h"
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <stdio.h>
struct monitor {
    unsigned int pids[64];
    int nroots;
    const char *sensitive;
    __u64 start_ns;
};
void json_string(const char *s);
int consume(void *ctx, void *data, size_t size);
void clear_rules(void);
int report_memory(struct bpf_object *obj, const struct monitor *m);
int attach_fixture_tls(struct bpf_object *obj, int pid, struct bpf_link **links, size_t *n);
