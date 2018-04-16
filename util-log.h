#ifndef __UTIL_LOG_H__
#define __UTIL_LOG_H__

#include "common.h"
#include "opts.h"
#include <syslog.h>

#define L_ALERT -3
#define L_CRIT  -2
#define L_ERR   -1
#define L_DEFAULT 0
#define L_WARN   1
#define L_NOTICE 2
#define L_INFO   3
#define L_DBG    4
#define L_MEM    5

#define PxyLog(lev, fmt, ...) fprintf(stderr, "%s():%d "fmt"\n", __func__, __LINE__, ## __VA_ARGS__)


int loger_init(opts_t*);
void loger_destroy();

#endif