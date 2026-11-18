#define _GNU_SOURCE
#include "monitor.h"
#include <dlfcn.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// TLS demo observes only the bundled loopback client, and only its registered PID.
int attach_fixture_tls(struct bpf_object *obj,int pid,struct bpf_link **links,size_t *n)
{
    char exe[PATH_MAX], proc[64];
    ssize_t len=readlink("/proc/self/exe",exe,sizeof(exe)-1);
    if (len<0) return -1;
    exe[len]=0;
    char *slash=strrchr(exe,'/');
    if (!slash || (size_t)(slash-exe)+sizeof("/demo-agent")>sizeof(exe)) return -1;
    strcpy(slash,"/demo-agent");
    snprintf(proc,sizeof(proc),"/proc/%d/exe",pid);
    struct stat local,target;
    if (stat(exe,&local) || stat(proc,&target) || local.st_dev!=target.st_dev || local.st_ino!=target.st_ino)
        return -1;

    void *lib=dlopen("libssl.so.3",RTLD_NOW);
    if (!lib) return -1;
    Dl_info info;
    const char *functions[]={"SSL_write","SSL_write","SSL_read","SSL_read"};
    const char *programs[]={"ssl_we","ssl_wr","ssl_re","ssl_rr"};
    int rc=-1;
    if (dladdr(dlsym(lib,"SSL_read"),&info)) {
        for (int i=0;i<4;i++) {
            struct bpf_uprobe_opts opts={.sz=sizeof(opts),.retprobe=(i%2),.func_name=functions[i]};
            struct bpf_program *p=bpf_object__find_program_by_name(obj,programs[i]);
            struct bpf_link *link=bpf_program__attach_uprobe_opts(p,pid,info.dli_fname,0,&opts);
            if (!link) goto done;
            links[(*n)++]=link;
        }
        rc=0;
    }
done:
    dlclose(lib);
    return rc;
}
