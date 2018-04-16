#ifndef __MESSAGE_H__
#define __MESSAGE_H__
#include "common.h"

#define MAX_MSG_LEN 1024

enum ERR_CODE{
    ERR_UNKNOWN_FORMAT = -1,
    ERR_EXCEPT_TYPE,
    ERR_UNREGISTERED,
    ERR_INFO_MISSED
};

enum MSG_TYPE{
    MSG_UNKNOWN = -1,
    MSG_REQ,
    MSG_RES,
    MSG_MAX
};

enum MTD_TYPE{
    MTD_ERR = -1,
    MTD_INIT,
    MTD_PING,
    MTD_OPT,
    MTD_MAX
};

#define MSG_TYPE    "Type"
#define MSG_METHOD  "Method"
#define MSG_ID      "MsgId"

#define SERVER_NAME "Server"
#define SERVER_ID   "ID"
#define SERVER_CAP  "Capabilitis"

#define CAP_ID      "ID"
#define CAP_DES     "Description"
#define CAP_LEVEL   "Level"


int message_error(int code, str *id, char *output, int *output_len);
void message_sender(int fd, char *data, int data_len);
int message_init_respond(str *id, char *output, int *output_len);
int message_ping(int type, str *id, char *buffer, int *len);
int message_parser(char *input, unsigned int input_len, char *output, unsigned int  *output_len);
#endif