#include "message.h"
#include "util-json.h"

#define MAX_ID_LEN 48

static char *err_format = "{\"Type\":1,\"State\":\"false\", \"MsgId\":\"%.*s\", \"Line\":\"400 Unkonw Format\"}";
static char *err_type = "{\"Type\":1,\"State\":\"false\", \"MsgId\":\"%.*s\", \"Line\":\"400 Except Message Type\"}";
static char *err_unreg = "{\"Type\":1,\"State\":\"false\"alse, \"MsgId\":\"%.*s\", \"Line\":\"403 Not Registered\"}";
static char *err_missed = "{\"Type\":1,\"State\":\"false\", \"MsgId\":\"%.*s\", \"Line\":\"400 Information Missed\"}";
static char *ping_format = "{\"Type\":%d, \"Method\":\"PING\", \"MsgId\":\"%d@tinyproxy\"}"; 
static char *init_format = "{\"Type\":1, \"State\":\"true\", \"Method\":\"INIT\", \"MsgId\":\"%.*s\"}"; 

static unsigned long global_ID = 0;

static unsigned long message_id_gen()
{
    return __sync_fetch_and_add(&global_ID, 1);
}


int method_str2enum(str *method){
    if(!method || !method->s || method->len == 0)
        return -1;
    
    switch(method->s[0]){
        case 'P':
        case 'p':
            return MTD_PING;
        case 'I':
        case 'i':
            return MTD_INIT;
        case 'O':
        case 'o':
            return MTD_OPT;
        default:
            return MTD_ERR;
    }
    return MTD_ERR;
}

void message_sender(int fd, char *data, int data_len)
{
    int ret, try = 0;
    
again:
    ret = send(fd, data, data_len, MSG_DONTWAIT);
    if(++try < 3 && ret == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)){
        PxyLog(L_WRN, "recv EINTR while sending msg, try again\n");
        goto again;
    }
}

int message_error(int code, str *id, char *output, int *output_len)
{
    char tmp[MAX_ID_LEN] = {0};
    str ID = {NULL, 0};
    
    if(!output || !output_len) return -1;
    
    if(!id || id->len == 0 || !id->s){
        ID.len = snprintf(tmp, MAX_ID_LEN-1, "%l@tinyproxy", message_id_gen());
        ID.s = tmp;
    }else{
        ID = *id;
    }
    
    switch(code){
        case ERR_UNKNOWN_FORMAT:
            *output_len = snprintf(output, MAX_MSG_LEN-1, err_format, ID.len, ID.s);
            break;
        case ERR_EXCEPT_TYPE:
            *output_len = snprintf(output, MAX_MSG_LEN-1, err_type, ID.len, ID.s);
            break;
        case ERR_UNREGISTERED:
            *output_len = snprintf(output, MAX_MSG_LEN-1, err_unreg, ID.len, ID.s);
            break;
        case ERR_INFO_MISSED:
            *output_len = snprintf(output, MAX_MSG_LEN-1, err_missed, ID.len, ID.s);
            break;
        default:
            PxyLog(L_ERR, "undefine error code %d", code);
            return -1;
    }
    if(*output_len > MAX_MSG_LEN-1){
        PxyLog(L_WRN, "may message too long to send\n");
    }
    return 0;
    
/*
    int try = 0;
again:
    ret = send(fd, buffer, len, MSG_DONTWAIT);
    if(try < 5 && ret == -1 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)){
        PxyLog(L_WRN, "recv EINTR while sending msg, try again\n");
        try++;
        goto again;
    }
*/

}

int message_init_respond(str *id, char *output, int *output_len)
{
    if(!id  || !id->s || id->len == 0 || !output)
        return -1;
       
    *output_len = snprintf(output, MAX_MSG_LEN-1, init_format, id->len, id->s);
    
    return 0;
}

int message_ping(int type, str *id, char *buffer, int *len)
{
    if(type < MSG_UNKNOWN || type > MSG_MAX || !buffer || !len ||
       (type == MSG_RES && (!id || !id->s)))return -1;
       
    *len = snprintf(buffer, MAX_MSG_LEN-1, ping_format, 
                    type == MSG_REQ ? MSG_REQ : MSG_RES, 
                    message_id_gen());

    return 0;
}


int message_parser(char *input, unsigned int input_len, char *output, unsigned int  *output_len)
{
    json_error_t err;
    int type, method_i;
    str id = {NULL, 0}, method = {NULL, 0};
    
    if(!input || input_len == 0 || !output || !output_len) return -1;
    
    json_t *root = json_loads(input, 0, &err);
    if(!root) {
        PxyLog(L_WARN, "not json format: on line %d: %s\n", err.line, err.text);
        PxyLog(L_WARN, "%.*s\n", input_len, input);
        //return message_error(ERR_UNKNOWN_FORMAT, NULL, output, output_len);
        return -1;
    }
    
    if(json_get_int(root, &type, MSG_TYPE) != 0){
        PxyLog(L_WARN, " msg missed %s\n%.*s", MSG_TYPE, input_len, input);
        return -1;
        //return message_error(ERR_INFO_MISSED, NULL, output, output_len);
    }
    
    if(json_get_str(root, &id, MSG_ID) != 0){
        PxyLog(L_WARN, "msg missed %s\n%.*s", MSG_ID, input_len, input);
        goto error;
        //return message_error(ERR_INFO_MISSED, NULL, output, output_len);
    }
    
    if(json_get_str(root, &method, MSG_METHOD) != 0){
        PxyLog(L_WARN, "msg missed %s\n%.*s", MSG_METHOD, input_len, input);
        message_error(ERR_INFO_MISSED, &id, output, output_len);
        goto done;
    }
    
    switch(method_str2enum(&method))
    {
        case MTD_INIT:
            //do northing
            break;
        case MTD_PING:
            if(MSG_TYPE == MSG_REQ)
                message_ping(MSG_RES, &id, output, output_len);
            
            //update last seen timestamp

            break;
        case MTD_OPT:
            break;
        default:
            break;
    }
    
done:
    if(id.s) PxyFree(id.s);
    if(method.s) PxyFree(method.s);
    
    return 0;
    
error:
    if(id.s) PxyFree(id.s);
    if(method.s) PxyFree(method.s);
    return -1;
}