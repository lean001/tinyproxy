#ifndef __UTIL_JSON_H__
#define __UTIL_JSON_H__

#include "common.h"
#include "util-str.h"
#include <jansson.h>

int json_get_str(json_t *, str *, const char *);
int json_get_int(json_t *, int *, const char *);


#endif