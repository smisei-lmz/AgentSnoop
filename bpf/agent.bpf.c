#include "events.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// Local CO-RE type views. Clang records field paths, not fixed target layouts.
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to=record)
struct task_struct { int tgid; struct task_struct *real_parent, *group_leader; __u64 start_boottime; };
struct trace_event_raw_sys_enter { unsigned long args[6]; };
struct trace_event_raw_sys_exit { long ret; };
struct trace_event_raw_kmalloc { const void *ptr; unsigned long bytes_alloc; };
struct trace_event_raw_kfree { const void *ptr; };
struct trace_event_raw_kmem_alloc { const void *ptr; unsigned long bytes_alloc; };
struct trace_event_raw_kmem_free { const void *ptr; };
struct pt_regs___arm { unsigned long regs[31]; };
struct pt_regs___x86 { unsigned long di, si, dx, ax; };
#pragma clang attribute pop

#define HASH(name, key_t, val_t, cap) struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,cap); __type(key,key_t); __type(value,val_t); } name SEC(".maps")
HASH(roots, __u32, struct root, 64);
HASH(pending, __u32, struct event, 4096);
HASH(live, __u64, struct allocation, 32768);
HASH(sites, struct site, __u64, 8192);
struct tls_call { __u64 buf; __u32 limit; };
HASH(tls_tx, __u64, struct tls_call, 256);
HASH(tls_rx, __u64, struct tls_call, 256);
struct { __uint(type,BPF_MAP_TYPE_STACK_TRACE); __uint(max_entries,4096); __uint(key_size,4); __uint(value_size,FRAMES*8); } stacks SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,1024*1024); } events SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,COUNTERS); __type(key,__u32); __type(value,__u64); } counts SEC(".maps");

static __always_inline void count(__u32 key)
{
    __u64 *n = bpf_map_lookup_elem(&counts, &key);
    if (n) (*n)++;
}
static __always_inline __u32 match(struct task_struct *task, __u32 pid)
{
    struct root *r = bpf_map_lookup_elem(&roots, &pid);
    if (!r || !r->ns_per_tick) return 0;
    return BPF_CORE_READ(task, start_boottime) / r->ns_per_tick == r->start_ticks ? pid : 0;
}
static __always_inline __u32 owner(void)
{
    struct task_struct *task = (void *)bpf_get_current_task();
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (match(leader, pid)) return pid;
    struct task_struct *parent = BPF_CORE_READ(leader, real_parent, group_leader);
    return match(parent, BPF_CORE_READ(parent, tgid));
}
static __always_inline void init(struct event *e, __u32 type, __u32 agent)
{
    __u64 id = bpf_get_current_pid_tgid();
    e->ns = bpf_ktime_get_ns();
    e->agent = agent; e->kind = type; e->pid = id >> 32; e->tid = id;
}
static __always_inline void emit(struct event *e)
{
    if (bpf_ringbuf_output(&events,e,sizeof(*e),0)) count(RING_DROP);
}
SEC("tracepoint/syscalls/sys_enter_openat")
int open_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 agent = owner();
    if (!agent) return 0;
    struct event e = {};
    init(&e, OPEN, agent);
    e.flags = ctx->args[2];
    long n = bpf_probe_read_user_str(e.text,sizeof(e.text),(void *)ctx->args[1]);
    if (n <= 0 || n == sizeof(e.text)) e.text[0] = 0; // avoid false matches on truncated paths
    if (bpf_map_update_elem(&pending,&e.tid,&e,BPF_ANY)) count(MAP_DROP);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_openat")
int open_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = bpf_get_current_pid_tgid();
    struct event *e = bpf_map_lookup_elem(&pending,&tid);
    if (e) {
        e->result = ctx->ret;
        e->ns = bpf_ktime_get_ns();
        emit(e);
        bpf_map_delete_elem(&pending,&tid);
    }
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_execve")
int exec_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 agent = owner();
    if (!agent) return 0;
    struct event e = {};
    init(&e,EXEC,agent);
    bpf_probe_read_user_str(e.text,sizeof(e.text),(void *)ctx->args[0]);
    emit(&e);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_write")
int write_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 agent = owner();
    if (!agent) return 0;
    struct event e = {};
    init(&e,WRITE,agent);
    e.flags = ctx->args[0]; e.result = ctx->args[2];
    emit(&e);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_connect")
int connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 agent = owner();
    if (!agent) return 0;
    struct { __u16 family, port; __u32 addr; } addr = {};
    if (ctx->args[2] < sizeof(addr) || bpf_probe_read_user(&addr,sizeof(addr),(void *)ctx->args[1]) || addr.family != 2) return 0;
    struct event e = {};
    init(&e,CONNECT,agent);
    e.ip = addr.addr; e.port = bpf_ntohs(addr.port);
    emit(&e);
    return 0;
}
SEC("tracepoint/kmem/kmalloc")
int alloc_trace(void *ctx)
{
    __u32 agent = owner();
    if (!agent) return 0;
    __u64 ptr, bytes;
    if (bpf_core_type_exists(struct trace_event_raw_kmalloc)) {
        struct trace_event_raw_kmalloc *k = ctx;
        ptr = (__u64)BPF_CORE_READ(k, ptr); bytes = BPF_CORE_READ(k, bytes_alloc);
    } else {
        struct trace_event_raw_kmem_alloc *k = ctx;
        ptr = (__u64)BPF_CORE_READ(k, ptr); bytes = BPF_CORE_READ(k, bytes_alloc);
    }
    if (ptr <= 16 || !bytes) return 0;
    struct allocation a = { .site.agent = agent, .bytes = bytes };
    a.site.stack = bpf_get_stackid(ctx,&stacks,0);
    if (a.site.stack < 0) count(STACK_FAIL);
    if (bpf_map_update_elem(&live,&ptr,&a,BPF_ANY)) count(MAP_DROP);
    count(ALLOCS);
    __u64 zero = 0;
    __u64 *total = bpf_map_lookup_elem(&sites,&a.site);
    if (!total) {
        bpf_map_update_elem(&sites,&a.site,&zero,BPF_NOEXIST);
        total = bpf_map_lookup_elem(&sites,&a.site);
    }
    if (total) __sync_fetch_and_add(total,bytes);
    else count(MAP_DROP);
    return 0;
}
SEC("tracepoint/kmem/kfree")
int free_trace(void *ctx)
{
    __u64 ptr;
    if (bpf_core_type_exists(struct trace_event_raw_kfree))
        ptr = (__u64)BPF_CORE_READ((struct trace_event_raw_kfree *)ctx, ptr);
    else
        ptr = (__u64)BPF_CORE_READ((struct trace_event_raw_kmem_free *)ctx, ptr);
    // Free can execute in a different process (including a kernel worker).
    if (ptr && !bpf_map_delete_elem(&live,&ptr)) count(FREES);
    return 0;
}
static __always_inline int tls_enter(void *ctx, void *map)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct tls_call s = {};
    if (bpf_core_field_exists(((struct pt_regs___arm *)ctx)->regs)) {
        struct pt_regs___arm *r = ctx;
        s.buf = BPF_CORE_READ(r, regs[1]); s.limit = BPF_CORE_READ(r, regs[2]);
    } else {
        struct pt_regs___x86 *r = ctx;
        s.buf = BPF_CORE_READ(r, si); s.limit = BPF_CORE_READ(r, dx);
    }
    if (bpf_map_update_elem(map,&id,&s,BPF_ANY)) count(MAP_DROP);
    return 0;
}
static __always_inline int tls_exit(void *ctx, void *map, __u32 type)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct tls_call *s = bpf_map_lookup_elem(map,&id);
    if (!s) return 0;
    int n;
    if (bpf_core_field_exists(((struct pt_regs___arm *)ctx)->regs))
        n = BPF_CORE_READ((struct pt_regs___arm *)ctx, regs[0]);
    else n = BPF_CORE_READ((struct pt_regs___x86 *)ctx, ax);
    // Only the opted-in demo-client PID has these uprobes attached.
    if (n > 0 && (__u32)n <= s->limit) {
        struct event e = {};
        __u64 length = (__u32)n;
        if (length > 64) length = 64;
        // Keep the verifier-visible bound even on kernels with older range tracking.
        asm volatile("" : "+r"(length));
        length &= 127;
        if (!bpf_probe_read_user(e.text,length,(void *)s->buf)) {
            init(&e,type,id >> 32);
            e.result = n;
            emit(&e);
        }
    }
    bpf_map_delete_elem(map,&id);
    return 0;
}
SEC("uprobe/SSL_write") int ssl_we(void *ctx) { return tls_enter(ctx,&tls_tx); }
SEC("uretprobe/SSL_write") int ssl_wr(void *ctx) { return tls_exit(ctx,&tls_tx,TLS_OUT); }
SEC("uprobe/SSL_read") int ssl_re(void *ctx) { return tls_enter(ctx,&tls_rx); }
SEC("uretprobe/SSL_read") int ssl_rr(void *ctx) { return tls_exit(ctx,&tls_rx,TLS_IN); }
char LICENSE[] SEC("license") = "GPL";
