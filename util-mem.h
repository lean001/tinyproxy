#ifndef __UTIL_MEM_H__
#define __UTIL_MEM_H__

#include <stdlib.h>

#define PxyMalloc( _size ) malloc(_size)

#define PxyFree( p ) free( p )

#endif