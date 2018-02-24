#include "server.h"
#include "util-mem.h"
#include "util-lock.h"
#include "common.h"

enum REG_STATE{
    NOT_REG = 0,
    REG_PENDING,
    REGISTERED,
    DEREGISTERED
};

typedef struct _capability{
    str id;
    str description;
    unsigned int level;
    struct _capability *next;
}capability_t;

typedef struct _s_contact{
    unsigned int hash;
    int fd;
    str server_id;
    enum REG_STATE state;
    str host;
    unsigned short port;
    str name;
    //time_t expires;
    capability_t *capabilities;
    struct _s_contact *next;
    struct _s_contact *prev;
}s_contact;

typedef struct _s_hash_slot{
    s_contact *head;
    s_contact *tail;
    gen_lock_t *lock;
}s_hash_slot;

s_hash_slot *s_contact_table = NULL;
int s_hash_size = DEFAULT_SERVER_HASH_SIZE;


inline void s_lock(unsigned int hash)
{
    lock_get(s_contact_table[(hash)].lock);
}

inline void s_unlock(unsigned int hash)
{
    lock_release(s_contact_table[(hash)].lock);
}

capability_t * s_capability_find(capability_t *capabilities, str id)
{
    capability_t *s;
    s = capabilities;
    while(s){
        if(s->id.len == id.len && strncasecmp(s->id.s, id.s, id.len) == 0)
            return s;
        s = s->next;
    }
    return NULL;
}

static void s_capability_free(capability_t *c)
{
    if(!c)return;
    if(c->id.s) PxyFree(c->id.s);
    if(c->description.s) PxyFree(c->description.s);
    PxyFree(c);
}

static void s_capability_destroy(capability_t *s)
{
    capability_t *tmp;
    
    while(s){
        tmp = s->next;
        s_capability_free(s);
        s = tmp;
    }
}

int s_contact_table_init(int size)
{
    s_hash_size = size;
    if(s_hash_size <= 0)
        s_hash_size = DEFAULT_SERVER_HASH_SIZE;
    
    s_contact_table = (s_hash_slot *)PxyMalloc(sizeof(s_hash_slot) * s_hash_size);
    if(!s_contact_table) return -1;
    memset(s_contact_table, 0, sizeof(s_hash_slot) * s_hash_size);
    
    
    for(i = 0; i < s_hash_size; i++){
        s_contact_table[i].lock = lock_alloc();
        if(!s_contact_table[i].lock){
            proxy_log(L_ERR, "%s failed to alloc lock hash=%d\n", __func__, i);
            return -1;
        }
        s_contact_table[i].lock = lock_init(s_contact_table[i].lock);
    }
    
    return 0;
}

void s_contact_table_destroy()
{
    unsigned int i;
    s_contact *c, *nc;
    
    if(!s_contact_table)return;
    
    for(i = 0; i < s_hash_size; i++){
        s_lock(i);
        c = s_contact_table[i].head;
        while(c){
            nc = c->next;
            s_contact_free(c);
            c = nc;
        }
        s_unlock(i);
        lock_dealloc(s_contact_table[i].lock);
    }
    PxyFree(s_contact_table);
}

inline static unsigned int s_contact_hash_get(str host, int port, int hash_size)
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

static s_contact* s_contact_new(int fd, str host, int port)
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
    c->hash = s_contact_hash_get(c->host, c->port, s_hash_size);
    c->state = NOT_REG;

    return c;
oom:
    if(c){
        PxyFree(c);
    }
    return NULL;
}

static void s_contact_free(s_contact *c)
{
    if(NULL == c)return;
    
    if(c->host.s) PxyFree(c->host.s);
    if(c->server_id.s) PxyFree(c->server_id.s);
    if(c->name.s) PxyFree(c->name.s);
    
    PxyFree(c);
}

static s_contact* s_contact_add(int fd, str host, int port)
{
    s_contact *c = NULL;
    
    if(!s_contact_table)return NULL;
    c = s_contact_new(fd, host, port);
    if(NULL == c) return NULL;
    c->next = NULL;
    
    unsigned int hash = c->hash;
    s_lock(hash);
    c->prev = s_contact_table[hash].tail;
    if(c->prev) c->prev->next = c;
    s_contact_table[hash].tail = c;
    if(!s_contact_table[hash].head) s_contact_table[hash].head = c;
    
    return c;
}

void s_contact_del(s_contact *c)
{
    unsigned int hash = c->hash;
    
    s_drop_all_dialogs(c->server_id);
    
    if(s_contact_table[hash]->head == c) s_contact_table[hash]->head = c->next;
    else c->prev->next = c->next;
    
    if(s_contact_table[hash]->tail == c) 
        s_contact_table[hash]->tail = c->prev;
    else c->next->prev = c->prev;
    
    s_contact_free(c);
}

s_contact* s_contact_get(str host, int port)
{
    s_contact *c;
    
    if(!s_contact_table) return NULL;
    unsigned int hash = s_contact_hash_get(host, port, s_hash_size);

    s_lock(hash);
    c = s_contact_table[hash].head;
    while(c){
        if(c->port == port && 
           c->host.len == host.len &&
           strncasecmp(c->host.s, host.s, host.len) == 0)
            return c;
        c = c->next;
    }
    s_unlock(hash);
    return NULL;
}

/*
* Update s_contact with the reg_state and capabilities, if not found , will be inserted.
* Note: will be lock on slot if success, so release it when you done.
* capabilities: the list of capability that the server supported, send nofify if updated success
*/
s_contact* s_contact_update(str host, int port, int fd, str *id, str *name, 
    enum REG_STATE *state, capability_t *capabilities)
{
    s_contact *c = NULL;
    
    c = s_contact_get(host, port);
    if(!c){
        c = s_contact_add(fd, host, port);
        if(!c) return NULL;
        
        if(id){
            if(c->server_id.s) PxyFree(c->server_id.s);
            STR_DUP(c->server_id, *id, "s_contact_update() server_id"); 
        }
        if(name){
            if(c->name.s) PxyFree(c->name.s);
            STR_DUP(c->name, *name, "s_contact_update() name"); 
        }
        if(capabilities){
            c->capabilities = capabilities;
        }
        
        c->state = NOT_REG;
    }else{
        if(state && *state != NOT_REG){
            c->state = *state;
            
            if(capabilities){
                if(!c->capabilities)c->capabilities = capabilities;
                else{ /* notify clients if need */
                    s_capability_destroy(c->capabilities);
                    c->capabilities = capabilities;
                }
            }
        }else{
            proxy_log(L_WARN, "update contact with NO state!");
        }
    }
    return c;
oom:
    proxy_log(L_ERR, "s_contact_update() some contacts might have not been updated!");
    return c;
}

typedef struct _s_conn_ctx{
    str host;
    int port;
    int fd;
    unsigned int marked : 1;
    struct event_base *evbase;
    struct event *ev;
}s_conn_ctx;

s_conn_ctx* s_conn_ctx_new(int fd, struct event_base *evbase)
{
    s_conn_ctx *ctx = NULL;
    
    BUG_ON(NULL == evbase);
    
    ctx = PxyMalloc(sizeof(s_conn_ctx));
    if(!ctx){
        proxy_log(L_ERR, "out of memory, alloc %d bytes failed\n", sizeof(s_conn_ctx));
        return NULL;
    }
    memset(ctx, 0, sizeof(s_conn_ctx));
    ctx->fd = fd;
    ctx->evbase = evbase;
    return ctx;
}

void s_conn_ctx_free(s_conn_ctx *ctx)
{
    if(!ctx)return;
    
    if(ctx->host.s) PxyFree(ctx->host.s);
    
    if (ctx->ev) {
        event_free(ctx->ev);
    }
    
    PxyFree(ctx);
}

void server_fd_readcb(evutil_socket_t fd, short what, void *arg)
{
    s_conn_ctx *ctx = (s_conn_ctx *)arg;
    
    if(!ctx->marked){
        char buf[1024];
        ssize_t n;
        int res;
        unsigned int complete;
        
        n = recv(fd, buf, sizeof(buf), MSG_PEEK);
        if(n < 0){
            proxy_log(L_ERR, "error on fd, aboring connnection\n");
            evutil_closesocket(fd);
            s_conn_ctx_free(ctx);
            return;
        }
        if(n == 0){
            proxy_log(L_DBG, "socket closed while waiting msg");
            evutil_closesocket(fd);
            s_conn_ctx_free(ctx);
            return;
        }
        #ifdef DEBUG
        printf("recv: %.*s\n", n, buf);
        #endif
        res = server_msg_parse(buf, n, &complete, &servername, &id, &capabilities);
        if(res == 1 && !complete){/*retry*/
            struct timeval delay = {0, 100};
            event_free(ctx->ev);
            ctx->ev = event_new(ctx->evbase, fd, 0, pxy_fd_readcb, ctx);
            if(!ctx->ev){
                perror("[Error] pxy_fd_readcb: Out of memory\n");
                evutil_closesocket(fd);
                conn_ctx_free(ctx);
                return;
            }
            event_add(ctx->ev, &delay);
            return;
        }
        event_free(ctx->ev);
        ctx->ev = NULL;
    }
    /*get server info*/
    s_contact_update(ctx->host, ctx->port, ctx->fd, capabilities);
}

/* server register setup */
void server_connect_setup(evutil_socket_t fd,
               struct sockaddr *peeraddr, int peeraddrlen,
               pxy_thrmgr_ctx_t *thrmgr, opts_t *opts)
{
    s_conn_ctx *ctx = NULL;
    struct event_base *evbase = (struct event_base *)arg;

    ctx = s_conn_ctx_new(fd, evbase);
    if(!ctx) goto error;
    
    if(addr2str(peeraddr, peeraddrlen, &ctx->host, &ctx->port) != 0) goto error;
    
    ctx->ev = event_new(evbase, fd, EV_READ, server_fd_readcb, ctx);
    if(!ctx->ev){
        proxy_log(L_ERR, "%s event_new: Out of memory!\n", __func__);
        goto error;
    }
    event_add(ctx->ev, NULL);
    return;
    
error:
    if(ctx) s_conn_ctx_free(ctx);
    evutil_closesocket(fd);
    return;
}