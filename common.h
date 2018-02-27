#ifndef __COMMON_H__
#define __COMMON_H__


#include <stdio.h>
#include "util-str.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h> 
#include <netdb.h>

int addr2str(struct sockaddr *, int , str *, int *);

#ifdef HAVE_ASSERT_H
#include <assert.h>
#define BUG_ON(x) assert(!(x))
#else
#define BUG_ON(x) if (((x))) exit(44)
#endif

#endif