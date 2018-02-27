#include "common.h"
#include "opts.h"
#include "middleware.h"
#include "server.h"
#include "client.h"
#include "dialog.h"


/* proxy -h host -p port --ci tcp/unix 127.0.0.1:9999 */

static int s_table_size = 128;
static int d_table_size = 128;
static int c_table_size = 128;

int main(int argc, char **argv)
{
    opts_t *opts = NULL;
    middleware_ctx *ctx = NULL;
    
    /*
    * Usage 
    */
    
    opts = opts_new(argc, argv);
    if(!opts) exit(EXIT_FAILURE);
        
    if(opts->daemon){
        PxyLog(L_DBG, "Detaching from TTY, see syslog for "
                "errors after this point\n");
        if (daemon(0, 0) == -1) {
            fprintf(stderr, "%s: failed to detach from TTY: %s\n", argv[0], strerror(errno));
            exit(EXIT_FAILURE);
        }
        //PxyLog_mode(LOG_MODE_SYSLOG);
    }
    if(loger_init(opts) != 0){
        exit(EXIT_FAILURE);
    }
    if(s_contact_table_init(s_table_size) != 0){
        exit(EXIT_FAILURE);
    }
    if(dialog_table_init(d_table_size) != 0){
        exit(EXIT_FAILURE);
    }
    if(c_contact_table_init(c_table_size) != 0){
        exit(EXIT_FAILURE);
    }
    ctx = middleware_new(opts);
    if(ctx == NULL){
        exit(EXIT_FAILURE);
    }
    middleware_run(ctx);
    
    dialog_table_destroy();
    c_contact_table_destroy();
    s_contact_table_destroy();
    
    loger_destroy();
    
    middleware_free(ctx);
    opts_free(opts);
    
    return 0;
}