#include "common.h"
#include "opts.h"
#include "proxy.h"

/* proxy -h host -p port --ci tcp/unix 127.0.0.1:9999 */

int s_hash_size = 128;
int d_hash_size = 128;
int c_hash_size = 128;

int main(int argc, char **argv)
{
    opts_t *opts = NULL;
    proxy_ctx_t *ctx = NULL;
    
    /*
    * Usage 
    */
    
    opts = opts_new(argc, argv);
    if(!opts) exit(EXIT_FAILURE)
        
    if(opts->daemon){
        proxy_log(L_DBG, "Detaching from TTY, see syslog for "
                "errors after this point\n");
        if (daemon(0, 0) == -1) {
            fprintf(stderr, "%s: failed to detach from TTY: %s\n",
                            argv0, strerror(errno));
            exit(EXIT_FAILURE);
        }
        proxy_log_mode(LOG_MODE_SYSLOG);
    }
    if(loger_init(opts) != 0){
        exit(EXIT_FAILURE);
    }
    if(s_contact_table_init(s_hash_size) != 0){
        exit(EXIT_FAILURE);
    }
    if(dialog_table_init(d_hash_size) != 0){
        exit(EXIT_FAILURE);
    }
    if(c_contact_table_destroy(c_hash_size) != 0){
        exit(EXIT_FAILURE);
    }
    ctx = proxy_new(opts);
    if(ctx == NULL){
        exit(EXIT_FAILURE);
    }
    proxy_run(ctx);
    
    dialog_table_destroy();
    c_contact_table_destroy();
    s_contact_table_destroy();
    
    loger_destroy();
    
    proxy_free(ctx);
    opts_free(opts);
    
    return 0;
}