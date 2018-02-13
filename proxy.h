#ifndef __PROXY_H__
#define __PROXY_H__

#include "opts.h"

typedef struct proxy_ctx proxy_ctx_t;

proxy_ctx_t * proxy_new(opts_t *, int);
void proxy_run(proxy_ctx_t *);
void proxy_loopbreak(proxy_ctx_t *);
void proxy_free(proxy_ctx_t *);

#endif

