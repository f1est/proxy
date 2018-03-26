/*
 * @author f1est 
 */
 
#include "parser.h"
#include "log.h"

#define SET_COOKIE_HEADER_MAX_NUM_OF_PARAMS 7 /* https://tools.ietf.org/html/rfc6265#section-4.1.1 */


/* return 1 if end of string, else return 0 */
static int check_end_of_string(char c)
{
        switch(c) {
                
                case '\0': 
                case '\n':
                case '\r': 
                        return 1;
                default:
                        return 0;
        }
}

/* 
 * check existence of a SID, and it not empty!
 * on success return pointer to value of SID (i.e. after SID=)
 * return NULL on fail
 */
const char *cookie_check_SID(struct evhttp_request* req)
{
        const char *cookie_value;
        const char *SID;
        int default_length_SID_name;
        
        cookie_value = evhttp_find_header(evhttp_request_get_input_headers(req),"Cookie");
        if(cookie_value == NULL)
                return NULL;

        SID = strstr(cookie_value, DEFAULT_SID_NAME);
        if(SID == NULL)
                return NULL;

        default_length_SID_name = strlen(DEFAULT_SID_NAME);
        
        /* cut DEFAULT_SID_NAME from SID. -1 because the '=' sign must also be cut off */
        while(default_length_SID_name != -1) {
                
                if(check_end_of_string(*SID) == 1)                        
                        return NULL;
                
                SID++;
                default_length_SID_name--;
        }

        /* check if SID is empty (i.e. Cookie: SID=\r\n ) */
        if(check_end_of_string(*SID) == 1)  
                return NULL;

        /* check if SID is empty (i.e. Cookie: SID=; OtherSID=value) */
        if(!isxdigit(*SID)) 
                return NULL;

        return SID;
}

/* return value needs to be deallocated by the caller */
/*
const char *cookie_get_SID(struct evhttp_request* req)
{
        int i = 0;
        int array_length;
        const char *SID;
        char *pureSID;
       
        if((SID = cookie_check_SID(req)) == NULL) 
                return NULL;

        array_length = strlen(SID) + 1;

        if((pureSID = malloc(array_length)) == NULL) 
                return NULL;
       
        memset(pureSID, '\0', array_length);


        while(i != array_length) {

                pureSID[i] = *SID;
                if(!isxdigit(pureSID[i])) {
                        pureSID[i] = '\0';
                        break;
                }

                i++;
                SID++;
        }
       
        return pureSID;
}
*/

/* 
 * Return NULL on fail,
 * on success return pointer on new allocated hashtable.
 * Return value needs to be deallocated by the caller 
 */
static hashtable_t *parse_header(struct evhttp_request* req, enum route_of_headers route_req, const char * header)
{
        const char *hdr;
        char *cpy;
        char *pos;
        char *sce;
        char *semicolon;
        char *equals;
        char *ekill;
        char old;
        int quotes;
        int count_pairs = 0;
        int length_cookie_value;
        hashtable_t *cookies_tbl;
        struct evkeyvalq *headers;
       
        switch(route_req) {
                case input:
                        headers = evhttp_request_get_input_headers(req);
                        break;
                case output:
                        headers = evhttp_request_get_output_headers(req);
                        break;
                default:
                        break;
        }

        hdr = evhttp_find_header(headers, header);
        if (hdr == NULL)
                return NULL;
                
        if((cpy = malloc(strlen(hdr) + 1)) == NULL) 
                return NULL;
                
        memcpy (cpy, hdr, strlen (hdr) + 1);
        
        length_cookie_value = strlen(hdr);

        pos = cpy;

        /* counting numbers of pairs key/value */
        while(length_cookie_value != 0) {
                if(*pos == ';')
                        count_pairs++;
                pos++;
                length_cookie_value--;
        }
 
        if((cookies_tbl = ht_create(count_pairs + 1)) == NULL) {
                if(cookies_tbl)
                        free((void *)cpy);
                return NULL;
        }
        
        pos = cpy;
        while (NULL != pos) {
                while (' ' == *pos)
                        pos++;                  /* skip spaces */
                        
                sce = pos;
                while ( ((*sce) != '\0') &&
                        ((*sce) != ';') &&
                        ((*sce) != '=') )
                        sce++;

                /* remove tailing whitespace (if any) from key */
                ekill = sce - 1;
                while ( (*ekill == ' ') &&
                        (ekill >= pos) )
                        *(ekill--) = '\0';
                old = *sce;
                *sce = '\0';
                
                if (old != '=')
                {
                        /* value part omitted, use empty string... */
                        if (ht_add(cookies_tbl, pos, "") < 0) {
                                if(cookies_tbl)
                                        ht_free(cookies_tbl);
                                if(cpy)
                                        free((void *)cpy);
                                return NULL;
                        }
                        
                        if (old == '\0')
                                break;
                        pos = sce + 1;
                        continue;
                }

                equals = sce + 1;
                quotes = 0;
                semicolon = equals;
                
                while ( ('\0' != semicolon[0]) &&
                        ( (0 != quotes) ||
                        (';' != semicolon[0]))) {
                        
                        if ('"' == semicolon[0])
                                quotes = (quotes + 1) & 1;
                        semicolon++;
                }
                
                if ('\0' == semicolon[0])
                        semicolon = NULL;
                if (NULL != semicolon) {
                        semicolon[0] = '\0';
                        semicolon++;
                }
                /* remove quotes */
                if ( ('"' == equals[0]) &&
                        ('"' == equals[strlen (equals) - 1]) ) {
                        equals[strlen (equals) - 1] = '\0';
                        equals++;
                }
                
                if (ht_add(cookies_tbl, pos, equals) < 0) {
                        if(cookies_tbl)
                                ht_free(cookies_tbl);
                        if(cpy)
                                free((void *)cpy);
                        return NULL;
                }
                pos = semicolon;
        }
        
        ht_print_table(cookies_tbl);
        
        if(cpy)
                free((void*)cpy);
        
        return cookies_tbl;
}

hashtable_t *parse_cookie_header(struct evhttp_request* req, enum route_of_headers route_req)
{
        return parse_header(req, route_req, "Cookie");
}

hashtable_t *parse_set_cookie_header(struct evhttp_request* req, enum route_of_headers route_req)
{
        return parse_header(req, route_req, "Set-Cookie");
}

hashtable_t *cookie_parse_ (struct evhttp_request* req)
{
        const char *cookie_value; /* all cookies in Cookie-header */
        const char *copy_cookie_value;
        size_t  length_cookie_value;
        size_t  tmp_length_cookie_value;
        char *key;
        char *value;
        hashtable_t *cookies_tbl;
        size_t count_pairs = 0;
        
        cookie_value = evhttp_find_header(evhttp_request_get_input_headers(req),"Cookie");
        if(cookie_value == NULL)
                return NULL;
        
        length_cookie_value = tmp_length_cookie_value = strlen(cookie_value);
        copy_cookie_value = cookie_value;

        /* counting numbers of pairs key/value */
        while(tmp_length_cookie_value != 0) {
                if(*copy_cookie_value == '=')
                        count_pairs++;
                copy_cookie_value++;
                tmp_length_cookie_value--;
        }

debug_msg("count_pairs = %zu", count_pairs);

        tmp_length_cookie_value = length_cookie_value + 1; 

        if((cookies_tbl = ht_create(count_pairs)) == NULL)
                return NULL;
        
        key = malloc(length_cookie_value);
        value = malloc(length_cookie_value);
        if(!key || !value) {
                if(cookies_tbl)
                        ht_free(cookies_tbl);
                return NULL;
        }
        memset((void*)key, '\0', length_cookie_value);
        memset((void*)value, '\0', length_cookie_value);

        /* filling keys/values */
        int is_key = 1;         /* boolean */
        int position = 0;

        for(; tmp_length_cookie_value != 0; position++, tmp_length_cookie_value--, cookie_value++) {
                
                if(position > length_cookie_value)
                        return NULL;
                

debug_msg("1 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ length_cookie_value = %zu tmp_length_cookie_value = %zu", length_cookie_value, tmp_length_cookie_value);
                if(!check_end_of_string(*cookie_value) &&  *cookie_value == '=') {
                        position = 0;
                        is_key = 0;
                        cookie_value++;
                        tmp_length_cookie_value--;
debug_msg("7 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ cookie_value == '='");
                }
       
                if(check_end_of_string(*cookie_value) || *cookie_value == ';') {
debug_msg("8 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ cookie_value == ';'");

                        if(*cookie_value == ';') {
                                cookie_value++; 
                                tmp_length_cookie_value--;
                                
                                /* remove all spases */
                                while(*cookie_value == ' ') {
                                        cookie_value++; 
                                        tmp_length_cookie_value--;
                                       
                                        if(check_end_of_string(*cookie_value)) {
                                                debug_msg("end of string");
                                                if(cookies_tbl)
                                                        ht_free(cookies_tbl);
                                                if(key)
                                                        free((void*)key);
                                                if(value)
                                                        free((void*)value);
                                                return NULL;
                                        }
                                }
                        }

                        is_key = 1;

                        if(!strlen(key) || !strlen(value)) {
                                debug_msg("WARNING: Key or Value is empty!!!");
                                if(cookies_tbl)
                                       ht_free(cookies_tbl);
                                if(key)
                                        free((void*)key);
                                if(value)
                                        free((void*)value);

                                return NULL;
                        }

                        debug_msg("Key = %s", key);
                        debug_msg("Value = %s", value);

                        ht_add(cookies_tbl, key, value);
                        
                        /* set our positions in begin and set to zero */
/*                        
                        key_position = key;
                        value_position = value;
*/
                        if(check_end_of_string(*cookie_value))
                                break;

                        position = 0;
                        memset((void*)key, '\0', length_cookie_value);
                        memset((void*)value, '\0', length_cookie_value);
                }

debug_msg("9 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ length_cookie_value = %zu tmp_length_cookie_value = %zu", length_cookie_value, tmp_length_cookie_value);
                if(is_key) {
                        
                        /* remove all spases */
                        while(*cookie_value == ' ') {
                                cookie_value++;
                                tmp_length_cookie_value--;
                                if(check_end_of_string(*cookie_value)) {

                                        debug_msg("end of string");
                                        if(cookies_tbl)
                                                ht_free(cookies_tbl);
                                        if(key)
                                                free((void*)key);
                                        if(value)
                                                free((void*)value);

                                        return NULL;
                                }
                        }

                        key[position] = *cookie_value;
debug_msg("10 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ key= '%s' strlen(key) = %lu", key, strlen(key));
                }
                else {
debug_msg("11 @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ value = '%s' strlen(value) = %lu", value, strlen(value));
                        value[position] = *cookie_value;
                }
        }
        
        
        if(key)
                free((void*)key);
        if(value)
                free((void*)value);

        ht_print_table(cookies_tbl);
        return cookies_tbl;
}
