#ifndef __STR_H__
#define __STR_H__

#include "util-log.h"
#include "util-mem.h"

struct _str{
	char* s; /*string*/
	int len; /*string len*/
};

typedef struct _str str;

#define STR_STATIC_INIT(v) {(v), sizeof(v) - 1}
#define STR_NULL {NULL, 0}

#define STR_FMT(_pstr_)	\
  ((_pstr_) ? (_pstr_)->len : 0), ((_pstr_) ? (_pstr_)->s : "")

#define STR_DUP(dest,src,txt)\
{\
    if ((src).len==0) {\
        (dest).s=0;\
        (dest).len=0;\
    }else {\
        (dest).s = PxyMalloc((src).len);\
        if (!(dest).s){\
            PxyLog(L_ERR,"ERR:"txt": Error allocating %d bytes\n",(src).len);\
            (dest).len = 0;\
            goto oom;\
        }else{\
            (dest).len = (src).len;\
            memcpy((dest).s,(src).s,(src).len);\
        }\
    }\
}


#endif
