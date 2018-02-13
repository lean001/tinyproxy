#ifndef __SERVER_H__
#define __SERVER_H__

#include "opts.h"
#include "pxythrmgr.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/util.h>

#define DEFAULT_SERVER_HASH_SIZE 128

int s_contact_hash_init(int);
void s_contact_hash_destroy();

void server_reg_setup(evutil_socket_t, struct sockaddr *, int,
                    pxy_thrmgr_ctx_t *, proxyspec_t *, opts_t *);

#endif