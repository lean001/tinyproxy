#ifndef __OPTS_H__
#define __OPTS_H__

typedef struct _opts{
    unsigned int debug:1;
    unsigned int daemon:1;
    char *host;
    int port;
    char *proxy_host;
    int proxy_port;
}opts_t;

opts_t* opts_new(int , char**);
void opts_free(opts_t*);

#define OPTS_DEBUG(p) (p)->debug

#endif