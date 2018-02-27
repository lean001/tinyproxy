#ifndef __SERVER_H__
#define __SERVER_H__

#include "opts.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/util.h>

#define DEFAULT_SERVER_HASH_SIZE 128

typedef struct _s_conn_ctx s_conn_ctx;
typedef struct _s_contact s_contact;

int s_contact_table_init(int);
void s_contact_table_destroy();

void server_connect_setup(evutil_socket_t, struct sockaddr *, int, void *);

#endif