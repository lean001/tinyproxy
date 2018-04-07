#include "opts.h"
#include "util-mem.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

opts_t* opts_new(int argc, char **argv)
{
    opts_t *p = NULL;
    char ch;
    
    if(argc < 2){
        fprintf(stderr, "Usage: %s -h 127.0.0.1 -p 2341\n", argv[0]);
        return NULL;
    }
    p = PxyMalloc(sizeof(opts_t));
    if(!p){
        fprintf(stderr, "failed to malloc for opts\n");
        return NULL;
    }
    memset(p, 0, sizeof(opts_t));
    while ((ch = getopt(argc, argv, "c:d:D:h:p:")) != -1) {
        switch(ch){
            case 'c':
                break;
            case 'd':
                p->daemon = 1;
                break;
            case 'D':
                p->debug = 1;
                break;
            case 'h':
                p->host = strdup(optarg);
                if(!p->host){
                    fprintf(stderr, "%s out of memory", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'p':
                p->port = atoi(optarg);
                break;
        }    
    }
    return p;
    
}
void opts_free(opts_t *p)
{
    if(!p) return;
    
    if(p->host) free(p->host);
    if(p->proxy_host) free(p->proxy_host);
    free(p);
}