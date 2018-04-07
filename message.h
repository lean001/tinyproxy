#ifndef __MESSAGE_H__
#define __MESSAGE_H__
#include "common.h"

enum ERR_CODE{
    ERR_UNKNOWN_FORMAT = -1,
    ERR_EXCEPT_TYPE,
    ERR_UNREGISTERED,
    ERR_INFO_MISSED
};


void msg_error_respond_fd(int, int, str*);
char * message_init_respond(str *id);

#endif