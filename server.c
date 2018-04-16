#include "server.h"
#include "common.h"

#include "util-lock.h"

#include "util-log.h"
#include "util-mem.h"
#include "util-json.h"

#include "message.h"

#include <assert.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>
#include <event2/thread.h>

enum REG_STATE{
    NOT_REG = 0,
    REG_PENDING,
    REGISTERED,
    DEREGISTERED
};

static str MHD_INIT_str = {"INIT", 4};
static str MHD_PING_str = {"PING", 4};
static str MHD_OPT_str  = {"OPT", 3};

typedef struct _capability{
    str id;
    str description;
    unsigned int level;
    struct _capability *next;
}capability_t;

struct _s_conn_ctx{
    str init_id;
    str host;
    int port;
    int fd;
    int reg_retry;
    unsigned int marked : 1;
    s_contact *contact;
    
    struct event_base *evbase;
    struct event *ev;
    struct bufferevent *bev;
};

struct _s_contact{
    unsigned int hash;
    int fd;
    unsigned int ref_count;
    str server_id;
    enum REG_STATE state;
    str host;
    unsigned short port;
    str name;
    //time_t expires;
    capability_t *capabilities;
    s_conn_ctx *server_ctx;
    
    struct _s_contact *next;
    struct _s_contact *prev;
};

typedef struct _s_hash_slot{
    s_contact *head;
    s_contact *tail;
    gen_lock_t *lock;
}s_hash_slot;

s_hash_slot *s_contact_table = NULL;
int s_hash_size = DEFAULT_SERVER_HASH_SIZE;


static void s_contact_del(s_contact *c);

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

static capability_t* s_capability_new()
{
    capability_t *c = NULL;
    
    c = PxyMalloc(sizeof(capability_t));
    if(!c){
        PxyLog(L_ERR, "Out of mem\n");
        return NULL;
    }
    memset(c, 0, sizeof(capability_t));
    return c;
}

static void s_capability_free(capability_t *c)
{
    if(!c)return;
    if(c->id.s) PxyFree(c->id.s);
    if(c->description.s) PxyFree(c->description.s);
    PxyFree(c);
}

capability_t * s_capability_add(capability_t *c, json_t *node)
{
    capability_t *n = NULL;
    if(!node) return NULL;
    
    n = s_capability_new();
    if(!n) return NULL;
    

    if(json_get_str(node, &n->id, CAP_ID) != 0){
        PxyLog(L_ERR, "The capability does not contain an ID!\n");
        goto error;
    }
    
    if(json_get_str(node, &n->description, CAP_DES) != 0){
        PxyLog(L_ERR, "The capability does not contain a description!\n");
        goto error;
    }
    
    if(json_get_int(node, &n->level, CAP_LEVEL) != 0){
        PxyLog(L_ERR, "The capability does not contain a level!\n");
        goto error;
    }
    
    if(c == NULL) c = n;
    else n->next = c;
    
    return n;
error:
    s_capability_free(c);
    return NULL;
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
    int i;
    s_hash_size = size;
    if(s_hash_size <= 0)
        s_hash_size = DEFAULT_SERVER_HASH_SIZE;
    
    s_contact_table = (s_hash_slot *)PxyMalloc(sizeof(s_hash_slot) * s_hash_size);
    if(!s_contact_table) return -1;
    memset(s_contact_table, 0, sizeof(s_hash_slot) * s_hash_size);
    
    
    for(i = 0; i < s_hash_size; i++){
        s_contact_table[i].lock = lock_alloc();
        if(!s_contact_table[i].lock){
            PxyLog(L_ERR, "%s failed to alloc lock hash=%d\n", __func__, i);
            return -1;
        }
        s_contact_table[i].lock = lock_init(s_contact_table[i].lock);
    }
    
    return 0;
}

void s_contact_table_destroy()
{
    int i;
    s_contact *c, *nc;
    
    if(!s_contact_table)return;
    
    for(i = 0; i < s_hash_size; i++){
        s_lock(i);
        c = s_contact_table[i].head;
        while(c){
            nc = c->next;
            s_contact_del(c);
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
        PxyLog(L_ERR, "out of memory, alloc %d bytes failed\n", sizeof(s_contact));
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

static void s_contact_del(s_contact *c)
{
    unsigned int hash = c->hash;
    if(c->ref_count)
        s_drop_all_dialogs(c);
    
    if(s_contact_table[hash].head == c) s_contact_table[hash].head = c->next;
    else c->prev->next = c->next;
    
    if(s_contact_table[hash].tail == c) 
        s_contact_table[hash].tail = c->prev;
    else c->next->prev = c->prev;
    
    s_contact_free(c);
}

int s_drop_all_dialogs(s_contact *c)
{
    //TODO
    return 0;
}

void s_contact_del_prv_lock(s_contact *c)
{
    unsigned int hash = c->hash;
    s_lock(hash);
    
    if(c->ref_count)
        s_drop_all_dialogs(c);
    if(s_contact_table[hash].head == c) s_contact_table[hash].head = c->next;
    else c->prev->next = c->next;
    
    if(s_contact_table[hash].tail == c) 
        s_contact_table[hash].tail = c->prev;
    else c->next->prev = c->prev;
   
    s_unlock(hash);
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
    enum REG_STATE state, capability_t *capabilities)
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
            if(!c->capabilities) c->capabilities = capabilities;
            else{ /* notify clients if need */
                s_capability_destroy(c->capabilities);
                c->capabilities = capabilities;
            }
        }
        c->state = state;
    }else{
        if(state != NOT_REG){
            c->state = state;
        }else{
            PxyLog(L_WARN, "update contact with NO state!");
        }
    }
    return c;
oom:
    PxyLog(L_ERR, "s_contact_update() some contacts might have not been updated!");
    return c;
}

s_contact* s_contact_update_connctx(s_conn_ctx *ctx, str *name, str *id,
            enum REG_STATE state, capability_t *capabilities)
{
    s_contact *c = NULL;
    
    if(!ctx) return NULL;
    
    c = s_contact_get(ctx->host, ctx->port);
    if(!c){
        c = s_contact_add(ctx->fd, ctx->host, ctx->port);
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
            if(!c->capabilities) c->capabilities = capabilities;
            else{ /* notify clients if need */
                s_capability_destroy(c->capabilities);
                c->capabilities = capabilities;
            }
        }
        c->state = state;
        c->server_ctx = ctx;
    }else{
        if(state != NOT_REG){
            c->state = state;
        }else{
            PxyLog(L_WARN, "update contact with NO state!");
        }
    }
    return c;
oom:
    PxyLog(L_ERR, "s_contact_update() some contacts might have not been updated!");
    return c;
}

s_conn_ctx* s_conn_ctx_new(int fd, struct event_base *evbase)
{
    s_conn_ctx *ctx = NULL;
    
    BUG_ON(NULL == evbase);
    
    ctx = PxyMalloc(sizeof(s_conn_ctx));
    if(!ctx){
        PxyLog(L_ERR, "out of memory, alloc %d bytes failed\n", sizeof(s_conn_ctx));
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
    
    if(ctx->init_id.s) PxyFree(ctx->init_id.s);
    if(ctx->host.s) PxyFree(ctx->host.s);
    
    if (ctx->ev) {
        event_free(ctx->ev);
    }
    
    if(ctx->bev){
        bufferevent_free(ctx->bev);
    }
    
    PxyFree(ctx);
}


int init_msg_parser(char *buf, size_t n, str *id, str *server, str *serverid, 
                    capability_t **capabilities)
{
    size_t size;
    int type = -1;
    int err_code = 0;
    json_error_t err;
    capability_t *cpt;
    str method = {NULL, 0};
    
    if(!buf || n == 0 || !server || !serverid || !capabilities || !id) return -1;
    
    json_t *root = json_loads(buf, 0, &err);
    if(!root) {
        PxyLog(L_WARN, "not json format: on line %d: %s\n", err.line, err.text);
        PxyLog(L_WARN, "%.*s\n", n, buf);
        return ERR_UNKNOWN_FORMAT;
    }
    
    if(json_get_int(root, &type, MSG_TYPE) != 0 || type != MSG_REQ){
        PxyLog(L_WARN, "Init msg must be a require\n");
        err_code = ERR_EXCEPT_TYPE;
        goto error;
    }
    
    if(json_get_str(root, id, MSG_ID) != 0){
        PxyLog(L_ERR, "%s get json %s value failed\n", __func__, MSG_ID);
        err_code = ERR_INFO_MISSED;
        goto error;
    }
    
    if(json_get_str(root, &method, MSG_METHOD) != 0){
        PxyLog(L_ERR, "%s get json %s value failed\n", __func__, MSG_METHOD);
        err_code = ERR_INFO_MISSED;
        if(method.s)PxyFree(method.s);
        err_code = ERR_INFO_MISSED;
        goto error;
    }
    if(MHD_INIT_str.len != method.len || strncasecmp(method.s, MHD_INIT_str.s, method.len) != 0){
        PxyLog(L_WARN, "must be register before method: %d %s\n", method.len, method.s);
        PxyFree(method.s);
        err_code = ERR_UNREGISTERED;
        goto error;
    }
    
    if(json_get_str(root, server, SERVER_NAME) != 0){
        PxyLog(L_ERR, "%s get json %s value failed\n", __func__, SERVER_NAME);
        err_code = ERR_INFO_MISSED;
        goto error;
    }
    
   if(json_get_str(root, serverid, SERVER_ID) != 0){
        PxyLog(L_ERR, "%s get json %s value failed\n", __func__, SERVER_ID);
        err_code = ERR_INFO_MISSED;
        goto error;
    }
    
    json_t *cap = NULL;
    json_t *child;
    if((cap = json_object_get(root, SERVER_CAP))){
        if(!json_is_array(cap)){
            PxyLog(L_ERR, "%s get json %s value failed: not a array\n", __func__, SERVER_CAP);
            return ERR_UNKNOWN_FORMAT;
            goto error;
        }
        size = json_array_size(cap);
        unsigned int i;
        cpt = NULL;
        capability_t *tmp = NULL;
        for(i = 0; i < size; i++){
            if((child = json_array_get(cap, i))){
                tmp = s_capability_add(cpt,child);
                if(tmp){
                    cpt = tmp;
                }
            }
        }
        if(!cpt){
            PxyLog(L_ERR, "The message does not contain a capability\n");
            err_code = ERR_INFO_MISSED;
            goto error;
        }
        *capabilities = cpt;
    }
    
    if(method.s)PxyFree(method.s);
    return 0;
    
error:
    if(server && server->s) PxyFree(server->s);
    if(serverid && serverid->s) PxyFree(serverid->s);
    if(root) json_decref(root);
    
    return err_code;
}

static void server_bev_eventcb(struct bufferevent *bev, short events, void *arg)
{
    s_conn_ctx *ctx = (s_conn_ctx *)arg;
    
    PxyLog(L_DBG, "%s%s%s%s\n",   
                events & BEV_EVENT_CONNECTED ? "connected" : "",
                events & BEV_EVENT_ERROR ? "error" : "",
                events & BEV_EVENT_TIMEOUT ? "timeout" : "",
                events & BEV_EVENT_EOF ? "eof" : "");
    if(events & BEV_EVENT_CONNECTED){
        //do northing
        return;
    }
    if(events & BEV_EVENT_ERROR || events & BEV_EVENT_EOF || events & BEV_EVENT_TIMEOUT){
        if(errno)
            PxyLog(L_ERR, "%s: Error from bufferevent %s", __func__, strerror(errno));
        
        s_contact_del_prv_lock(ctx->contact);
        evutil_closesocket(ctx->fd);
        s_conn_ctx_free(ctx);
        return;
    }
}

static void server_bev_readcb(struct bufferevent *bev, void *arg)
{
    char res_buf[MAX_MSG_LEN] = {0};
    char *line = NULL;
    s_conn_ctx *ctx = (s_conn_ctx *)arg;
    
    struct evbuffer *inbuf = bufferevent_get_input(bev);
    struct evbuffer *outbuf = bufferevent_get_output(bev);
    
    unsigned int len = 0, inbuf_len = 0;
    
    inbuf_len = evbuffer_get_length(inbuf);
    if(inbuf_len == 0) return;
    
    if(!ctx->marked && 
        message_init_respond(&ctx->init_id, res_buf, (int *)&len) == 0) {
        evbuffer_add_printf(outbuf, "%.*s", len, res_buf);
        line = NULL;
        ctx->marked = 1;
        evbuffer_drain(inbuf, inbuf_len);
        return;
    }
    

    /* TODO: 
    evbuffer_copyout(buf, &record_len, 4); 
    record_len = ntohl(record_len);
    if(record_len < len)return;
    line = PxyMalloc(record_len);
    */
    line = PxyMalloc(inbuf_len);
    if(NULL == line) return;
    evbuffer_remove(inbuf, line, inbuf_len);
    line[inbuf_len] = '\0';
    if(message_parser(line, inbuf_len, res_buf, &len) == 0 && len != 0){
        evbuffer_add(outbuf, res_buf, len);
    }
    PxyFree(line);
    return;
    
#if 0
    while((line = evbuffer_readln(inbuf, &size, EVBUFFER_EOL_CRLF))){
        PxyLog(L_DBG, "%s\n", line);
        /*parser msg*/
        //server_msg_parse();
        len += size;
        PxyFree(line);
    }
#endif
    
    
    /* respond to server or not need to */
    //evbuffer_add_buffer(outbuf, inbuf);
}

static void server_bev_writecb(struct bufferevent *bev, void *arg)
{
    return;
}

static struct bufferevent *
server_bufferevent_setup(s_conn_ctx *ctx)
{
    struct bufferevent *bev = NULL;
    bev = bufferevent_socket_new(ctx->evbase, ctx->fd,
                        BEV_OPT_DEFER_CALLBACKS);
    if(!bev){
        PxyLog(L_ERR, "%s: out of mem!\n", __func__);
        return NULL;
    }
    bufferevent_setcb(bev, server_bev_readcb, NULL/*server_bev_writecb*/,
                      server_bev_eventcb, ctx);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    return bev;
}

static void server_bev_heartbeatcb(evutil_socket_t fd, short what, void *arg)
{
    char buffer[MAX_MSG_LEN];
    unsigned int len = 0;
    
    s_conn_ctx *ctx = (s_conn_ctx *)arg;
    
    if (what & EV_TIMEOUT && ctx && ctx->bev) {
        struct evbuffer *outbuf = bufferevent_get_output(ctx->bev);
        if(outbuf && message_ping(MSG_REQ, NULL, buffer, &len) == 0 && len != 0){
            evbuffer_add(outbuf, buffer, len);
        }
    }
}

static void server_fd_readcb(evutil_socket_t fd, short what, void *arg)
{
    str servername = {NULL, 0}, serverid = { NULL, 0}, msg_id = {NULL, 0};
    capability_t *capabilities = NULL;
    
    s_conn_ctx *ctx = (s_conn_ctx *)arg;
    
    if(!ctx->marked){
        char buf[MAX_MSG_LEN];
        ssize_t n;
        int res;
        unsigned int complete;
        
        n = recv(fd, buf, sizeof(buf), MSG_PEEK);
        if(n < 0){
            PxyLog(L_ERR, "error on fd, aboring connnection\n");
            evutil_closesocket(fd);
            s_conn_ctx_free(ctx);
            return;
        }
        if(n == 0){
            PxyLog(L_DBG, "socket closed while waiting msg");
            evutil_closesocket(fd);
            s_conn_ctx_free(ctx);
            return;
        }
        
        PxyLog(L_DBG, "recv: %.*s\n", n, buf);
        buf[n] = '\0';
        res = init_msg_parser((char *)buf, n, &msg_id, &servername, &serverid, &capabilities);
        if(res != 0 && ctx->reg_retry < 10) {/*retry*/
            struct timeval delay = {0, 100};
            
            event_free(ctx->ev);/* must be free before respond to server */
            if(message_error(res, &msg_id, buf, (int *)&n) == 0){
                message_sender(fd, buf, n);
            }
            if(msg_id.s){
                PxyFree(msg_id.s);
                msg_id.s = NULL;
                msg_id.len = 0;
            }
            ctx->ev = event_new(ctx->evbase, fd, 0, server_fd_readcb, ctx);
            if(!ctx->ev){
                PxyLog(L_ERR, "%s: event_new Out of memory\n", __func__);
                evutil_closesocket(fd);
                s_conn_ctx_free(ctx);
                return;
            }
            event_add(ctx->ev, &delay);
            ctx->reg_retry++;
            return;
        }
        event_free(ctx->ev);
        ctx->ev = NULL;
    }
    /*get server info*/
    s_contact *c = s_contact_update_connctx(ctx, &servername, &serverid, REGISTERED, capabilities);
    if(c){
        ctx->init_id = msg_id;
        ctx->contact = c;
        ctx->bev = server_bufferevent_setup(ctx);
        s_unlock(c->hash); 
        /* add ping timer */
        if(ctx->ev)event_free(ctx->ev);
        ctx->ev = event_new(ctx->evbase, fd, EV_TIMEOUT|EV_PERSIST, server_bev_heartbeatcb, ctx);
        struct timeval delay = {3, 500};
        event_add(ctx->ev, &delay);
        return;
    }
    /*It can't be here! */
    BUG_ON(c == NULL);
}

/* server register setup */
void server_connect_setup(evutil_socket_t fd,
               struct sockaddr *peeraddr, int peeraddrlen, void *arg)
{
    s_conn_ctx *ctx = NULL;
    struct event_base *evbase = (struct event_base *)arg;

    ctx = s_conn_ctx_new(fd, evbase);
    if(!ctx) goto error;
    
    if(addr2str(peeraddr, peeraddrlen, &ctx->host, &ctx->port) != 0) goto error;
    
    ctx->ev = event_new(evbase, fd, EV_READ, server_fd_readcb, ctx);
    if(!ctx->ev){
        PxyLog(L_ERR, "%s event_new: Out of memory!\n", __func__);
        goto error;
    }
    event_add(ctx->ev, NULL);
    return;
    
error:
    if(ctx) s_conn_ctx_free(ctx);
    evutil_closesocket(fd);
    return;
}