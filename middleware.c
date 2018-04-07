/*
 * SSLsplit - transparent SSL/TLS interception
 * Copyright (c) 2009-2016, Daniel Roethlisberger <daniel@roe.ch>
 * All rights reserved.
 * http://www.roe.ch/SSLsplit
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "middleware.h"
#include "common.h"
#include "server.h"


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <event2/thread.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>


/*
 * middleware engine, built around libevent 2.x.
 */

static int signals[] = { SIGQUIT, SIGHUP, SIGINT, SIGPIPE, SIGUSR1 };

struct _middleware_ctx {
    //middleware_thrmgr_ctx *thrmgr;
    struct event_base *evbase;
    struct event *sev[sizeof(signals)/sizeof(int)];
    //struct event *gcev;
    //struct middleware_ctx *lctx;
    opts_t *opts;
};


/*
 * Callback for accept events on the socket listener bufferevent.
 */
static void
middleware_listener_acceptcb(struct evconnlistener *listener,
                        evutil_socket_t fd,
                        struct sockaddr *peeraddr, int peeraddrlen,
                        void *arg)
{
    server_connect_setup(fd, peeraddr, peeraddrlen, arg);
}

/*
 * Callback for error events on the socket listener bufferevent.
 */
static void
middleware_listener_errorcb(struct evconnlistener *listener, void *ctx)
{
    struct event_base *evbase = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    PxyLog(L_ERR,"Error %d on listener: %s\n", err,
                   evutil_socket_error_to_string(err));
    event_base_loopbreak(evbase);
}

/*
 * Dump a description of an evbase to debugging code.
 */
static void
middleware_debug_base(const struct event_base *ev_base)
{
    PxyLog(L_DBG,"Using libevent backend '%s'\n",
                   event_base_get_method(ev_base));

    enum event_method_feature f;
    f = event_base_get_features(ev_base);
    PxyLog(L_DBG,"Event base supports: edge %s, O(1) %s, anyfd %s\n",
                   ((f & EV_FEATURE_ET) ? "yes" : "no"),
                   ((f & EV_FEATURE_O1) ? "yes" : "no"),
                   ((f & EV_FEATURE_FDS) ? "yes" : "no"));
}

/*
 * Set up the listener for a single proxyspec and add it to evbase.
 * Returns the proxy_listener_ctx_t pointer if successful, NULL otherwise.
 */
static int
middleware_listener_setup(struct event_base *evbase, opts_t *opts)
{
    struct evconnlistener *evconnl = NULL;
    struct sockaddr_in sin;
    
    sin.sin_family = AF_INET;
    inet_aton(opts->host, &sin.sin_addr.s_addr);
    sin.sin_port = htons(opts->port);

    evconnl = evconnlistener_new_bind(evbase, middleware_listener_acceptcb, 
                            (void *)evbase/*args for callback*/, 
                            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
                            1024, (struct sockaddr *)&sin, sizeof(sin));
    if(!evconnl){
        PxyLog(L_ERR, "%s %s:%d", strerror(errno), opts->host, opts->port);
        return -1;
    }
    evconnlistener_set_error_cb(evconnl, middleware_listener_errorcb);
    return 0;
}

/*
 * Signal handler for SIGQUIT, SIGINT, SIGHUP, SIGPIPE and SIGUSR1.
 */
static void
middleware_signal_cb(evutil_socket_t fd, short what, void *arg)
{
    middleware_ctx *ctx = arg;

    PxyLog(L_DBG,"Received signal %i\n", fd);

    switch(fd) {
    case SIGQUIT:
    case SIGINT:
    case SIGHUP:
        middleware_loopbreak(ctx);
        break;
    case SIGUSR1:
        break;
    case SIGPIPE:
        PxyLog(L_ERR,"Warning: Received SIGPIPE; ignoring.\n");
        break;
    default:
        PxyLog(L_ERR,"Warning: Received unexpected signal %i\n", fd);
        break;
    }
}



/*
 * Set up the core event loop.
 * Socket clisock is the privsep client socket used for binding to ports.
 * Returns ctx on success, or NULL on error.
 */
middleware_ctx * middleware_new(opts_t *opts)
{
    middleware_ctx *ctx;
    int rc;
    size_t i;

    /* adds locking, only required if accessed from separate threads */
    //evthread_use_pthreads();

    #ifndef PURIFY
    if (OPTS_DEBUG(opts)) {
        event_enable_debug_mode();
    }
    #endif /* PURIFY */

    ctx = PxyMalloc(sizeof(middleware_ctx));
    if (!ctx) {
        PxyLog(L_ERR,"Error allocating memory\n");
        goto leave0;
    }
    memset(ctx, 0, sizeof(middleware_ctx));

    ctx->opts = opts;
    struct event_config *cfg = event_config_new();

    event_config_avoid_method(cfg, "epoll");

    ctx->evbase = event_base_new_with_config(cfg); 
    //ctx->evbase = event_base_new();
    if (!ctx->evbase) {
        PxyLog(L_ERR,"Error getting event base\n");
        goto leave1;
    }

    if (OPTS_DEBUG(opts)) {
        middleware_debug_base(ctx->evbase);
    }

    if(middleware_listener_setup(ctx->evbase, opts) < 0){
        goto leave1b;
    }

    for (i = 0; i < (sizeof(signals) / sizeof(int)); i++) {
        ctx->sev[i] = evsignal_new(ctx->evbase, signals[i],
                                   middleware_signal_cb, ctx);
        if (!ctx->sev[i])
            goto leave3;
        evsignal_add(ctx->sev[i], NULL);
    }

    return ctx;

leave3:
    for (i = 0; i < (sizeof(ctx->sev) / sizeof(ctx->sev[0])); i++) {
        if (ctx->sev[i]) {
            event_free(ctx->sev[i]);
        }
    }
    
leave1b:
    event_base_free(ctx->evbase);
leave1:
    free(ctx);
leave0:
    return NULL;
}

/*
 * Run the event loop.  Returns when the event loop is cancelled by a signal
 * or on failure.
 */
void
middleware_run(middleware_ctx *ctx)
{
    if (ctx->opts->daemon) {
        event_reinit(ctx->evbase);
    }
    #ifndef PURIFY
    if (OPTS_DEBUG(ctx->opts)) {
        event_base_dump_events(ctx->evbase, stderr);
    }
    #endif /* PURIFY */
/*    
    if (pxy_thrmgr_run(ctx->thrmgr) == -1) {
        PxyLog(L_ERR,"Failed to start thread manager\n");
        return;
    }
*/
    PxyLog(L_DBG,"Starting main event loop.\n");
    event_base_dispatch(ctx->evbase);
    PxyLog(L_DBG,"Main event loop stopped.\n");
}

/*
 * Break the loop of the proxy, causing the proxy_run to return.
 */
void
middleware_loopbreak(middleware_ctx *ctx)
{
    event_base_loopbreak(ctx->evbase);
}

/*
 * Free the proxy data structures.
 */
void
middleware_free(middleware_ctx *ctx)
{
    size_t i;
    for (i = 0; i < (sizeof(ctx->sev) / sizeof(ctx->sev[0])); i++) {
        if (ctx->sev[i]) {
            event_free(ctx->sev[i]);
        }
    }
    /*
    if (ctx->thrmgr) {
        pxy_thrmgr_free(ctx->thrmgr);
    }
    */
    if (ctx->evbase) {
        event_base_free(ctx->evbase);
    }
    free(ctx);
}

/* vim: set noet ft=c: */
