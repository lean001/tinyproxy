#ifndef __UTIL_MEM_H__
#define __UTIL_MEM_H__

#include <stdlib.h>
#include <string.h>

#define PxyMalloc( _size ) malloc(_size)

#define PxyFree( p ) free( p )

#define PxyStrdup(src, len) strndup(src, (len))
#endif