#ifndef __MIDDLEWARE_H__
#define __MIDDLEWARE_H__

#include "opts.h"

typedef struct _middleware_ctx middleware_ctx;

middleware_ctx * middleware_new(opts_t *);
void middleware_run(middleware_ctx *);
void middleware_loopbreak(middleware_ctx *);
void middleware_free(middleware_ctx *);

#endif

