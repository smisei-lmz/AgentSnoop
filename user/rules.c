#include "monitor.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void json_string(const char *s)
{
    putchar('"');
    for (const unsigned char *p=(const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p >= 127) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

struct path_state {
    struct path_state *next;
    char path[PATH_BYTES];
    unsigned int count[64];
    int first_writer;
    bool shared;
};
static struct path_state *buckets[1024];
static size_t entries;
static __u64 window;
void clear_rules(void)
{
    for (size_t i=0; i<1024; i++) {
        while (buckets[i]) {
            struct path_state *old = buckets[i];
            buckets[i] = old->next;
            free(old);
        }
    }
    entries = 0;
}
static struct path_state *state_for(const char *path)
{
    unsigned h = 2166136261u;
    for (const unsigned char *p=(const unsigned char *)path; *p; p++)
        h = (h ^ *p) * 16777619u;
    struct path_state **head = &buckets[h % 1024];
    for (struct path_state *s=*head; s; s=s->next)
        if (!strcmp(s->path,path)) return s;
    if (entries >= 16384) return NULL;
    struct path_state *s = calloc(1,sizeof(*s));
    if (!s) return NULL;
    strcpy(s->path,path);
    s->first_writer = -1;
    s->next = *head;
    *head = s;
    entries++;
    return s;
}
static void alert(const struct event *e, const char *rule, int other, unsigned hits)
{
    printf("{\"type\":\"alert\",\"rule\":\"%s\",\"agent\":%u,\"pid\":%u,\"tid\":%u,\"ns\":%llu,\"ret\":%lld,\"path\":",rule,e->agent,e->pid,e->tid,e->ns,e->result);
    json_string(e->text);
    if (other > 0) printf(",\"other_agent\":%d",other);
    if (hits) printf(",\"count\":%u",hits);
    puts("}");
}
static int check_open(const struct event *e,const struct monitor *m)
{
    if (!strcmp(e->text,m->sensitive)) alert(e,"sensitive_open",0,0);
    if (e->result < 0 || e->text[0] != '/') return 0;
    int index = 0;
    while (index < m->nroots && m->pids[index] != e->agent) index++;
    if (index == m->nroots) return 0;
    // Fixed ten-second windows on the monotonic ingestion clock.
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    __u64 bucket = (((__u64)ts.tv_sec*1000000000 + ts.tv_nsec)-m->start_ns)/10000000000ULL;
    if (window != bucket) { clear_rules(); window = bucket; }
    struct path_state *s = state_for(e->text);
    if (!s) { fputs("rule window capacity exhausted\n",stderr); return -1; }
    if (++s->count[index] == 20) alert(e,"repeated_open",0,20);
    unsigned mode = e->flags & O_ACCMODE;
    if (mode == O_WRONLY || mode == O_RDWR) {
        if (s->first_writer < 0) s->first_writer = index;
        else if (index != s->first_writer && !s->shared) {
            alert(e,"shared_writable_open",m->pids[s->first_writer],0);
            s->shared = true;
        }
    }
    return 0;
}
int consume(void *ctx,void *data,size_t size)
{
    const struct event *e = data;
    static const char *const kinds[] = {"","openat","execve","connect","write","ssl_write","ssl_read"};
    if (size != sizeof(*e) || !e->kind || e->kind >= sizeof(kinds)/sizeof(*kinds)) return -1;
    printf("{\"type\":\"event\",\"event\":\"%s\",\"agent\":%u,\"pid\":%u,\"tid\":%u,\"ns\":%llu", kinds[e->kind],e->agent,e->pid,e->tid,e->ns);
    if (e->kind == OPEN || e->kind == EXEC) { printf(",\"path\":"); json_string(e->text); }
    if (e->kind == OPEN) printf(",\"flags\":%u,\"ret\":%lld",e->flags,e->result);
    if (e->kind == WRITE) printf(",\"fd\":%u,\"requested\":%lld",e->flags,e->result);
    if (e->kind == CONNECT) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&e->ip,ip,sizeof(ip));
        printf(",\"ip\":\"%s\",\"port\":%u",ip,e->port);
    }
    if (e->kind == TLS_IN || e->kind == TLS_OUT) {
        printf(",\"bytes\":%lld,\"message\":",e->result);
        json_string(e->text);
    }
    puts("}");
    return e->kind == OPEN ? check_open(e,ctx) : 0;
}
