/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "parser.h"
#include "log.h"
#include "config.h"

/* return 1 if end of string, else return 0 */
int check_end_of_string(char c)
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
 * Return NULL on fail,
 * on success return pointer on new allocated hashtable.
 * Return value needs to be deallocated by the caller 
 */
static hashtable_t *_parse_header(const char *hdr)
{
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
        string_t data;
        int max_num_of_cookies = -1;
        int max_length_of_cookie = -1;

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
        
        if((max_num_of_cookies = config_get_max_num_of_cookies()) < 0)
                max_num_of_cookies = MAX_NUM_OF_COOKIES;
        
        if((max_length_of_cookie = config_get_max_length_of_cookie()) < 0)
                max_length_of_cookie = MAX_LENGTH_OF_COOKIE;

        if(count_pairs > max_num_of_cookies)
                count_pairs = max_num_of_cookies;
 
        if((cookies_tbl = ht_create(count_pairs + 1)) == NULL) {
                if(cpy)
                        free((void *)cpy);
                return NULL;
        }
        
        pos = cpy;
        while (pos != NULL) {
                while (*pos == ' ' || 
                        *pos == ';' ||
                        *pos == ':')
                        pos++;                  /* skip spaces, colons(:) and semicolons (;) from start string*/
                         
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

                        if(strlen(pos) > max_length_of_cookie) {
                                if (old == '\0')
                                        break;
                                pos = sce + 1;
                                continue;
                        }

                        st_string_t_init(&data,"");

                        ht_add(cookies_tbl, pos, (base_t*)&data); 
                        
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
                if (semicolon != NULL) {
                        semicolon[0] = '\0';
                        semicolon++;
                }
                /* remove quotes */
                if ( ('"' == equals[0]) &&
                        ('"' == equals[strlen (equals) - 1]) ) {
                        equals[strlen (equals) - 1] = '\0';
                        equals++;
                }
                
               
                if(strlen(pos) + strlen(equals) > max_length_of_cookie) {
                        pos = semicolon;
                        continue;
                }
 
                st_string_t_init(&data, equals);
                ht_add(cookies_tbl, pos, (base_t*)&data);
                
                pos = semicolon;
        }
        
        ht_print_table(cookies_tbl);
        
        if(cpy)
                free((void*)cpy);
        
        return cookies_tbl;
}

hashtable_t *_parse_cookie_header(const char *header_value)
{
        return _parse_header(header_value);
}

hashtable_t *_parse_set_cookie_header(const char *header_value)
{
        return _parse_header(header_value);
}
