#include "message.h"
//#include ""

#define MAX_ID_LEN 48

static char *err_format = "{\"Type\":1,\"State\":\"false\", \"MsgId\":\"%.*s\", \"Line\":\"400 Unkonw Format\"}";
static char *err_type = "{\"Type\":1,\"State\":\"false\", \"MsgId\":\"%.*s\", \"Line\":\"400 Except Message Type\"}";
static char *err_unreg = "{\"Type\":1,\"State\":\"false\"alse, \"MsgId\":\"%.*s\", \"Line\":\"403 Not Registered\"}";
static char *err_missed = "{\"Type\":1,\"State\":\"false\", \"MsgId\":\"%.*s\", \"Line\":\"400 Information Missed\"}";
static char *ping_str = "{\"Type\":0, \"Method\":\"PING\", \"MsgId\":\"%l@tinyproxy\"}"; 
static char *init_format = "{\"Type\":1, \"State\":\"true\", \"Method\":\"INIT\", \"MsgId\":\"%.*s\"}"; 

static unsigned long global_ID = 0;

static unsigned long message_id_gen()
{
    return __sync_fetch_and_add(&global_ID, 1);
}

void msg_error_respond_fd( int fd, int  code, str *id)
{
    char buffer[1024] = {0};
    char tmp[MAX_ID_LEN] = {0};
    str ID = {NULL, 0};
    int ret, len = 0;
    
    if(!id || id->len == 0 || !id->s){
        ID.len = snprintf(tmp, MAX_ID_LEN-1, "%l@tinyproxy", message_id_gen());
        ID.s = tmp;
    }else{
        ID = *id;
    }
    
    switch(code){
        case ERR_UNKNOWN_FORMAT:
            len = snprintf(buffer, sizeof(buffer), err_format, ID.len, ID.s);
            break;
        case ERR_EXCEPT_TYPE:
            len = snprintf(buffer, sizeof(buffer), err_type, ID.len, ID.s);
            break;
        case ERR_UNREGISTERED:
            len = snprintf(buffer, sizeof(buffer), err_unreg, ID.len, ID.s);
            break;
        case ERR_INFO_MISSED:
            len = snprintf(buffer, sizeof(buffer), err_missed, ID.len, ID.s);
            break;
        default:
            /*
            len = snprintf(buffer, sizeof(buffer), ping_str, message_id_gen());
            break;
            */
            PxyLog(L_ERR, "undefine error code %d", code);
            return;
    }
    if(len > sizeof(buffer)){
        PxyLog(L_WRN, "message too long to send\n");
        len = sizeof(buffer);
    }
    int try = 0;
again:
    ret = send(fd, buffer, len, MSG_DONTWAIT);
    if(try < 5 && ret == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)){
        PxyLog(L_WRN, "recv EINTR while sending msg, try again\n");
        try++;
        goto again;
    }
}

char * message_init_respond(str *id)
{
    char *line = NULL;
    if(!id  || !id->s || id->len == 0)
        return NULL;
    
    char buffer[1024] = {0};
    
    int len = snprintf(buffer, sizeof(buffer), init_format, id->len, id->s);
    
    line  = PxyStrdup(buffer, len);
    return line;
}