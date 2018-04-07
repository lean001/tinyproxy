#include "util-json.h"

int json_get_str(json_t *root, str *s, const char *key)
{
    if(!root || !s || !key) return -1;
    
    json_t *value;
    if((value = json_object_get(root, key)) && json_is_string(value)){
        size_t size = json_string_length(value);
        if(size > 0){
            s->s = PxyMalloc(size + 1);
            if(!s->s){
                PxyLog(L_CRIT, "%s Out of mem\n", __func__);
                return -1;
            }
            //printf("%d %s", size, json_string_value(value));
            s->len = snprintf(s->s, size+1, "%s", json_string_value(value));
            return 0;
        }
    }
    PxyLog(L_DBG, "key: %s not found or not string value\n", key);
    return -1;
}
int json_get_int(json_t *root, int *value, const char *key)
{
    if(!root || !value || !key) return -1;
    
    json_t *v;
    if((v = json_object_get(root, key)) && json_is_integer(v)){
        *value = json_integer_value(v);
        return 0;
    }
    PxyLog(L_DBG, "key: %s not found or not string value\n", key);
    return -1;
}

