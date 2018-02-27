#ifndef __UTIL_LOCK_H__
#define __UTIL_LOCK_H__


#define USE_PTHREAD_MUTEX

#ifdef USE_PTHREAD_MUTEX
#include "util-mem.h"

#include<pthread.h>

typedef pthread_mutex_t gen_lock_t;

#define lock_destroy(lock) /* do nothing */ 

inline static gen_lock_t* lock_init(gen_lock_t* lock)
{
    if (pthread_mutex_init(lock, 0)==0) return lock;
    else return 0;
}


#define lock_alloc() PxyMalloc(sizeof(gen_lock_t))
#define lock_dealloc(lock) PxyFree((void*)lock)

#define lock_try(lock) pthread_mutex_trylock(lock)
#define lock_get(lock) pthread_mutex_lock(lock)
#define lock_release(lock) pthread_mutex_unlock(lock)
#endif

#endif