#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int exchange(int port,const char *cert)
{
    SSL_CTX *ctx=SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    SSL *ssl=SSL_new(ctx);
    int fd=socket(AF_INET,SOCK_STREAM,0), rc=-1;
    struct sockaddr_in dst={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    char reply[16]={};
    if (ssl && fd>=0 && SSL_CTX_load_verify_locations(ctx,cert,NULL)==1 &&
        !connect(fd,(struct sockaddr *)&dst,sizeof(dst)) && SSL_set_fd(ssl,fd)==1 &&
        SSL_set1_host(ssl,"localhost")==1 && SSL_connect(ssl)==1 &&
        SSL_write(ssl,"agent-demo/ping",15)==15 && SSL_read(ssl,reply,15)==15 &&
        !memcmp(reply,"agent-demo/pong",15)) rc=0;
    SSL_free(ssl); SSL_CTX_free(ctx);
    if (fd>=0) close(fd);
    return rc;
}
int main(int argc,char **argv)
{
    if (argc!=5) return 2;
    int a=!strcmp(argv[1],"A");
    char config[512], secret[512], shared[512];
    snprintf(config,sizeof(config),"%s/config",argv[2]);
    snprintf(secret,sizeof(secret),"%s/secret.demo",argv[2]);
    snprintf(shared,sizeof(shared),"%s/shared",argv[2]);
    puts("ready"); fflush(stdout);
    if (getchar()==EOF) return 1;
    for (int i=0;i<(a?25:1);i++) {
        int fd=open(config,O_RDONLY);
        if (fd<0) return 1;
        close(fd);
    }
    if (a) {
        // The fixture intentionally leaves the sensitive path absent.
        int fd=open(secret,O_RDONLY);
        if (fd>=0) close(fd);
        pid_t child=fork();
        if (child==0) { execl("/bin/cat","cat",config,(char *)NULL); _exit(127); }
        int status;
        if (child<0 || waitpid(child,&status,0)<0 || status) return 1;
        if (atoi(argv[3]) && exchange(atoi(argv[3]),argv[4])) return 1;
    }
    int fd=open(shared,O_RDWR);
    if (fd<0 || write(fd,"x",1)!=1) return 1;
    puts("done"); fflush(stdout);
    getchar(); // Keep roots alive until the monitor has taken its final snapshot.
    close(fd);
    return 0;
}
