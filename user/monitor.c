#define _GNU_SOURCE
#include "monitor.h"
#include <bpf/bpf.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping=1; }
static int pid_number(const char *s)
{
    char *end;
    errno=0;
    long n=strtol(s,&end,10);
    return errno || *end || n<=0 || n>INT_MAX ? -1 : (int)n;
}
static int register_pid(int fd,__u32 pid)
{
    char path[64],*line=NULL;
    size_t cap=0;
    snprintf(path,sizeof(path),"/proc/%u/stat",pid);
    FILE *f=fopen(path,"r");
    if (!f) return -1;
    int ok=getline(&line,&cap,f)>0;
    fclose(f);
    char *end=ok ? strrchr(line,')') : NULL;
    char *save=NULL,*field=end ? strtok_r(end+1," ",&save) : NULL;
    for (int i=3;i<22 && field;i++) field=strtok_r(NULL," ",&save);
    long hz=sysconf(_SC_CLK_TCK);
    int rc=-1;
    if (field && hz>0 && 1000000000L%hz==0) {
        struct root value={.start_ticks=strtoull(field,NULL,10),.ns_per_tick=1000000000L/hz};
        rc=bpf_map_update_elem(fd,&pid,&value,BPF_NOEXIST);
    }
    free(line);
    return rc;
}
int main(int argc,char **argv)
{
    struct monitor m={};
    const char *object="agent.bpf.o";
    int tls_pid=0;
    for (int i=1;i<argc;i++) {
        if (i+1==argc) goto usage;
        const char *opt=argv[i],*value=argv[++i];
        if (!strcmp(opt,"--pid") && m.nroots<64 && pid_number(value)>0)
            m.pids[m.nroots++]=pid_number(value);
        else if (!strcmp(opt,"--sensitive") && value[0]=='/' && strlen(value)<PATH_BYTES-1) m.sensitive=value;
        else if (!strcmp(opt,"--object")) object=value;
        else if (!strcmp(opt,"--tls-demo") && pid_number(value)>0) tls_pid=pid_number(value);
        else goto usage;
    }
    if (!m.nroots || !m.sensitive) goto usage;
    if (tls_pid) {
        bool registered=false;
        for (int i=0;i<m.nroots;i++) if (m.pids[i]==(unsigned)tls_pid) registered=true;
        if (!registered) goto usage;
    }
    signal(SIGINT,stop); signal(SIGTERM,stop);
    struct rlimit lim={RLIM_INFINITY,RLIM_INFINITY};
    (void)setrlimit(RLIMIT_MEMLOCK,&lim);
    setvbuf(stdout,NULL,_IOLBF,0);
    struct bpf_object *obj=bpf_object__open_file(object,NULL);
    if (!obj || libbpf_get_error(obj)) { perror("open BPF object"); return 1; }
    struct ring_buffer *rb=NULL;
    struct bpf_link *links[16];
    size_t n=0;
    int rc=1;
    struct bpf_program *p;
    bpf_object__for_each_program(p,obj) {
        if (!tls_pid && !strncmp(bpf_program__name(p),"ssl_",4)) bpf_program__set_autoload(p,false);
    }
    if (bpf_object__load(obj)) goto done;
    int root_fd=bpf_object__find_map_fd_by_name(obj,"roots");
    for (int i=0;i<m.nroots;i++)
        if (register_pid(root_fd,m.pids[i])) { perror("register PID"); goto done; }
    rb=ring_buffer__new(bpf_object__find_map_fd_by_name(obj,"events"),consume,&m,NULL);
    if (!rb || libbpf_get_error(rb)) { rb=NULL; goto done; }
    bpf_object__for_each_program(p,obj) {
        if (!strncmp(bpf_program__name(p),"ssl_",4)) continue;
        struct bpf_link *link=bpf_program__attach(p);
        if (!link || libbpf_get_error(link)) { fprintf(stderr,"attach failed: %s\n",bpf_program__name(p)); goto done; }
        links[n++]=link;
    }
    if (tls_pid && attach_fixture_tls(obj,tls_pid,links,&n)) { perror("attach fixture TLS"); goto done; }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC,&ts);
    m.start_ns=(__u64)ts.tv_sec*1000000000+ts.tv_nsec;
    puts("{\"type\":\"ready\"}");
    rc=0;
    while (!stopping) {
        int err=ring_buffer__poll(rb,100);
        if (err<0 && err!=-EINTR) { rc=1; break; }
    }
done:
    while (n) bpf_link__destroy(links[--n]);
    if (!rc && (ring_buffer__consume(rb)<0 || report_memory(obj,&m))) rc=1;
    if (rb) ring_buffer__free(rb);
    bpf_object__close(obj);
    clear_rules();
    return rc || ferror(stdout);
usage:
    fprintf(stderr,"usage: %s --pid PID [--pid PID ...] --sensitive /absolute/path [--tls-demo PID] [--object path]\n",argv[0]);
    return 2;
}
