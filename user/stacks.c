#include "monitor.h"
#include <bpf/bpf.h>
#include <stdlib.h>
#include <string.h>

struct symbol { unsigned long long addr; char name[128]; };
static int by_addr(const void *a,const void *b)
{
    const struct symbol *x=a, *y=b;
    return (x->addr > y->addr) - (x->addr < y->addr);
}
static struct symbol *read_symbols(size_t *used)
{
    FILE *f = fopen("/proc/kallsyms","r");
    if (!f) return NULL;
    char line[512], type, name[128];
    unsigned long long addr;
    struct symbol *arr = NULL;
    size_t cap = 0;
    while (fgets(line,sizeof(line),f)) {
        if (sscanf(line,"%llx %c %127s",&addr,&type,name) != 3 || !addr || !strchr("tTwW",type)) continue;
        if (*used == cap) {
            cap = cap ? cap*2 : 8192;
            struct symbol *more = realloc(arr,cap*sizeof(*arr));
            if (!more) { free(arr); arr=NULL; *used=0; break; }
            arr = more;
        }
        arr[*used].addr=addr; strcpy(arr[*used].name,name); (*used)++;
    }
    fclose(f);
    if (arr) qsort(arr,*used,sizeof(*arr),by_addr);
    return arr;
}
static void print_frame(const struct symbol *s,size_t n,__u64 ip)
{
    size_t lo=0,hi=n;
    while (lo<hi) {
        size_t mid=lo+(hi-lo)/2;
        if (s[mid].addr <= ip) lo=mid+1;
        else hi=mid;
    }
    json_string(lo ? s[lo-1].name : "[unresolved]");
}
int report_memory(struct bpf_object *obj,const struct monitor *m)
{
    int live=bpf_object__find_map_fd_by_name(obj,"live"), sites=bpf_object__find_map_fd_by_name(obj,"sites");
    int stacks=bpf_object__find_map_fd_by_name(obj,"stacks");
    const int slots=4097; // final slot groups samples whose stack capture failed
    __u64 *out=calloc((size_t)m->nroots*slots,sizeof(*out));
    if (!out) return -1;
    __u64 ptr, next;
    void *prev=NULL;
    while (!bpf_map_get_next_key(live,prev,&next)) {
        struct allocation a;
        ptr=next; prev=&ptr;
        if (bpf_map_lookup_elem(live,&ptr,&a)) continue;
        for (int i=0; i<m->nroots; i++)
            if (m->pids[i] == a.site.agent)
                out[i*slots + (a.site.stack < 0 ? slots-1 : a.site.stack)] += a.bytes;
    }
    size_t n=0;
    struct symbol *syms=read_symbols(&n);
    struct site site, next_site;
    prev=NULL;
    while (!bpf_map_get_next_key(sites,prev,&next_site)) {
        site=next_site; prev=&site;
        __u64 total=0, ips[FRAMES]={}, outstanding=0;
        if (bpf_map_lookup_elem(sites,&site,&total)) continue;
        for (int i=0; i<m->nroots; i++)
            if (m->pids[i]==site.agent)
                outstanding=out[i*slots+(site.stack<0 ? slots-1 : site.stack)];
        printf("{\"type\":\"allocation_site\",\"agent\":%u,\"stack_id\":%d,\"allocated_bytes\":%llu,\"outstanding_bytes\":%llu,\"frames\":[",site.agent,site.stack,total,outstanding);
        if (site.stack >= 0 && !bpf_map_lookup_elem(stacks,&site.stack,ips))
            for (size_t i=0; i<FRAMES && ips[i]; i++) {
                if (i) putchar(',');
                print_frame(syms,n,ips[i]);
            }
        puts("]}");
    }
    free(syms); free(out);
    int fd=bpf_object__find_map_fd_by_name(obj,"counts");
    int cpus=libbpf_num_possible_cpus();
    if (cpus <= 0) return -1;
    __u64 *percpu=calloc(cpus,sizeof(*percpu)), totals[COUNTERS]={};
    if (!percpu) return -1;
    for (unsigned i=0; i<COUNTERS; i++) {
        if (bpf_map_lookup_elem(fd,&i,percpu)) { free(percpu); return -1; }
        for (int c=0;c<cpus;c++) totals[i]+=percpu[c];
    }
    printf("{\"type\":\"health\",\"ring_drops\":%llu,\"map_drops\":%llu,\"stack_failures\":%llu,\"allocations\":%llu,\"matched_frees\":%llu}\n",totals[0],totals[1],totals[2],totals[3],totals[4]);
    free(percpu);
    return 0;
}
