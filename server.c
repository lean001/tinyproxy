#include "server.h"
#include ""util-mem.h

enum REG_STATE{
    NOT_REG = 0,
    REG_PENDING,
    REGISTERED,
    DEREGISTERED
};

typedef struct _s_contact{
    int hash;
    int fd;
    str server_id;
    enum REG_STATE state;
    str host;
    unsigned short port;
    str name;
    //time_t expires;
    
    struct _s_contact *next;
    struct _s_contact *prev;
}s_contact;

typedef struct {
    s_contact *table;
    int count;
}s_hash_slot;


s_hash_slot s_contact_hash = {NULL, 0};
int r_hash_size = DEFAULT_SERVER_HASH_SIZE;

int s_contact_hash_init(int size)
{
    r_hash_size = size;
    if(r_hash_size <= 0)
        r_hash_size = DEFAULT_SERVER_HASH_SIZE;
    
    s_contact_hash.table = (s_contact *)PxyMalloc(sizeof(s_contact) * r_hash_size);
    if(!s_contact_hash.table) return -1;
    
    memset(s_contact_hash.table, 0, sizeof(s_contact) * r_hash_size);
    s_contact_hash.count = 0;
    
    return 0;
}
void s_contact_hash_destroy()
{
    
}

inline unsigned int get_s_contact_hash(str host, int port, int hash_size)
{
   #define h_inc h+=v^(v>>3)
   char* p;
   register unsigned v;
   register unsigned h;

   h=0;
   for (p=host.s; p<=(host.s+host.len-4); p+=4){
       v=(*p<<24)+(p[1]<<16)+(p[2]<<8)+p[3];
       h_inc;
   }
   v=0;
   for (;p<(host.s+host.len); p++) {
       v<<=8;
       v+=*p;
   }
   h_inc;
   v = port;
   h_inc;

   h=((h)+(h>>11))+((h>>13)+(h>>23));
   return (h)%hash_size;
#undef h_inc 
}

s_contact* s_contact_new(int fd, str host, int port)
{
    s_contact* c = NULL;
    
    c = (s_contact*)PxyMalloc(sizeof(s_contact));
    if(!c){
        proxy_log(L_ERR, "out of memory, alloc %d bytes failed\n", sizeof(s_contact));
        goto oom;
    }
    memset(c, 0, sizeof(s_contact));
    
    
    STR_DUP(c->host, host, "s_contact_new");
    c->fd = fd;
    c->port = port;
    c->hash = get_s_contact_hash(c->host, c->port, r_hash_size);
    c->state = NOT_REG;
    return c;
    
oom:
    if(c){
        PxyFree(c);
    }
    return NULL;
}

/* server register setup */
void
server_reg_setup(evutil_socket_t fd,
               struct sockaddr *peeraddr, int peeraddrlen,
               pxy_thrmgr_ctx_t *thrmgr,
               proxyspec_t *spec, opts_t *opts)
{
    
}