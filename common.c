#include "common.h"
#include "util-log.h"
#include  "util-mem.h"


int addr2str(struct sockaddr *addr, int addrlen, str *host, int *port)
{
    char tmphost[INET6_ADDRSTRLEN];
    char tmpport[8];
    int rv;
    size_t hostsz;

    rv = getnameinfo(addr, addrlen,
                 tmphost, sizeof(tmphost),
                 tmpport, 8,
                 NI_NUMERICHOST | NI_NUMERICSERV);
    if (rv != 0) {
        PxyLog(L_ERR, "Cannot get nameinfo for socket address: %s\n",
                       gai_strerror(rv));
        return -1;
    }
    
    *port = atoi(tmpport);
    
    hostsz = strlen(tmphost) + 1; /* including terminator */
    host->s = (char *)PxyMalloc(hostsz);
    if (!host->s) {
        PxyLog(L_ERR, "Cannot allocate memory\n");
        return -1;
    }
    host->len = hostsz;
    memcpy(host->s, tmphost, hostsz);
    
    return 0;
}