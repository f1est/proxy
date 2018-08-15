/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "session.h"
#include "transport.h"
#include "parser.h"

#define SOURCE_OF_PSEUDORANDOM "/dev/urandom"

/* 
 * generate pseudorandom 
 * return 0 on success, -1 on filure.
 */
static int get_random_bytes(void *data, size_t size)
{

        FILE *fp;
        size_t cnt = 0;
        fp = fopen(SOURCE_OF_PSEUDORANDOM, "r");
        
        if(!fp) {
                debug_msg("Couldn't open '%s'. Error: %s\n", SOURCE_OF_PSEUDORANDOM, strerror(errno));
                return -1;
        }
        
        cnt = fread(data, 1, size, fp);

        if(cnt < size)
                debug_msg("Read not enough data. Only %zu bytes, but it should be %zu", cnt, size );

        fclose(fp);
        return 0;
}

static void bin_to_readable(const void *in, char *out, size_t size, req_proxy_to_server_t *proxy_req)
{
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        char tmp[] = "\0\0";
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len, i;
        const char *user_agent;

        user_agent = evhttp_find_header(evhttp_request_get_input_headers(proxy_req->req_client_to_proxy), "User-Agent");
        
        
        OpenSSL_add_all_digests();
        
        md = EVP_sha256();
        
        if(!md) {
                debug_msg("Unknown message digest");
                return;
        }
        
        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, in, strlen(in));

        /* add a sources of entropy */
        EVP_DigestUpdate(mdctx, SOURCE_OF_PSEUDORANDOM, sizeof(SOURCE_OF_PSEUDORANDOM));
        EVP_DigestUpdate(mdctx, user_agent, strlen(user_agent));

        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_destroy(mdctx);
        for(i = 0; (i < md_len) && (strlen(out) < size); i++) {
                sprintf(tmp, "%02x", md_value[i]);
                strncat(out, tmp, 2);
        }
}

/* 
 * create Session ID 
 * return length of SID on succes, or -1 on failure 
 */ 
int session_create_id(req_proxy_to_server_t *proxy_req, char *SID)
{
	unsigned char rbuf[MAX_RANDOM_BYTES_LENGTH + EXTRA_RAND_BYTES];
        int res;

        memset(SID, '\0', MAX_SID_LENGTH);
        
        if (get_random_bytes(rbuf, MAX_RANDOM_BYTES_LENGTH) != 0) 
		return -1;
	
        bin_to_readable(rbuf, SID, (MAX_SID_LENGTH) - 2, proxy_req);

        if((res = strlen(SID)) > 0)
                return res;
        else 
                return -1;
}


/*
 * create cookie-name
 * return cookie-name on success or NULL on failure
 */
const char *session_create_name()
{
        return DEFAULT_EMBEDDED_SID_NAME;
}

/* 
 * return 0 if header Cookie not exist 
 * return -1 if Cookie-header exist, but it have not EmbeddedSID. 
 * return 1 if Cookie-header exist and it have EmbeddedSID
 */ 
int cookie_check(struct evhttp_request *req_client_to_proxy)
{
        extern http_proxy_core_t *proxy_core;

        /* check if Cookie-header not exist */
        if(!evhttp_find_header(evhttp_request_get_input_headers(req_client_to_proxy),"Cookie"))        
                return 0;
        
        /* check if EmbeddedSID not exist in Cookie-header */
        if(cookie_check_EmbeddedSID(req_client_to_proxy) == NULL)   
                return -1;
        
        return 1;      
}

/*
 * concatenate and return string of all pairs of cookies
 * Return NULL on fail, return pointer on new allocated string. 
 * Because in this function used malloc and realloc,
 * return value needs to be deallocated by the caller. 
 * if @param cut_key not NULL, it will be cut
 */
const char *_cookie_get_all_pairs_as_string(hashtable_t *hashtable, const char * cut_key)
{
#define SIZE_OF_STRING_ALL_ENTRIES 128
        char *str;
        entry_t *hashtable_entry = NULL;
        size_t size_str = SIZE_OF_STRING_ALL_ENTRIES;
        size_t i;
        if(hashtable == NULL)
                return NULL;

        if((str = malloc(size_str)) == NULL)
                return NULL;

        memset(str, '\0', size_str);

        for(i = 0; i < ht_get_size(hashtable); i++) {

                if((hashtable_entry = ht_get_entry_on_index(hashtable, i)) != NULL) {

                        size_t tmp_size = 0;

                        /* cutting cut_key */
                        if(cut_key) {
                               if((tmp_size = strlen(cut_key)) > 0) {
                                       if(strncmp(hashtable_entry->key, cut_key, tmp_size) == 0) {
                                               continue;
                                       }
                               }
                        }


                                
                        tmp_size = strlen(str) + 
                                        strlen(hashtable_entry->key) +
                                        strlen(";") + strlen("=");
                        
                        if(hashtable_entry->value->type == type_string)
                                tmp_size += strlen(((string_t *)hashtable_entry->value)->str);

                        if(tmp_size > size_str) {
                                size_str += tmp_size;
                                str = realloc(str, size_str);
                        }

                        if((tmp_size = strlen(hashtable_entry->key)) == 0) {
                                if(str)
                                        free((void*)str);
                                return NULL;
                        }
                        
                        if(strlen(str) != 0)
                                strncat(str, "; ", 2);
                                
                        strncat(str, hashtable_entry->key, tmp_size);
                        
                        if(hashtable_entry->value->type == type_string) {

                                if((tmp_size = strlen(((string_t *)hashtable_entry->value)->str)) != 0) {
                                        strncat(str, "=", 1);
                                        strncat(str, ((string_t *)hashtable_entry->value)->str, tmp_size);
                                }
                        }
                }
        }

        return str;
}

/* 
 * check existence of a EmbeddedSID, and it not empty!
 * on success return pointer to value of EmbeddedSID (i.e. after EmbeddedSID=)
 * return NULL on fail
 */
const char *cookie_check_EmbeddedSID(struct evhttp_request* req)
{
        const char *cookie_value;
        const char *SID;
        int default_length_EmbeddedSID_name;
        
        cookie_value = evhttp_find_header(evhttp_request_get_input_headers(req),"Cookie");
        if(cookie_value == NULL)
                return NULL;

        SID = strstr(cookie_value, DEFAULT_EMBEDDED_SID_NAME);
        if(SID == NULL)
                return NULL;

        default_length_EmbeddedSID_name = strlen(DEFAULT_EMBEDDED_SID_NAME);
        
        /* cut DEFAULT_EMBEDDED_SID_NAME from SID. -1 because the '=' sign must also be cut off */
        while(default_length_EmbeddedSID_name != -1) {
                
                if(check_end_of_string(*SID) == 1)                        
                        return NULL;
                
                SID++;
                default_length_EmbeddedSID_name--;
        }

        /* check if SID is empty (i.e. Cookie: EmbeddedSID=\r\n ) */
        if(check_end_of_string(*SID) == 1)  
                return NULL;

        /* check if SID is empty (i.e. Cookie: EmbeddedSID=; OtherSID=value) */
        if(!isxdigit(*SID)) 
                return NULL;

        return SID;
}

/* 
 * check existence the EmbeddedSID in hashtable of SID's and 
 * check the validity it and to belong to IP-address and User-agent of client
 * return -1 on failure, 0 on success
 */
int check_valid_EmbeddedSID(req_proxy_to_server_t * proxy_req)
{
        extern http_proxy_core_t *proxy_core; 
        session_t *session;
        
        const char *SID_value;
        
        if(!proxy_core)
                return -1;

        if(!proxy_core->SIDs)
                return -1;

        if(!proxy_req)
                return -1;

        if(!proxy_req->cookies_tbl)
                return -1;
        
        if((SID_value = st_string_t_get_str((string_t*)ht_get_value(proxy_req->cookies_tbl, DEFAULT_EMBEDDED_SID_NAME))) == NULL)
                return -1;
       
        if((session = (session_t*)ht_get_value(proxy_core->SIDs, SID_value)) == NULL) 
                return -1;

        if(strlen(SID_value) > 0 &&
                strlen(SID_value) == strlen(session->SID) &&
                strncmp((SID_value), session->SID, strlen(session->SID)) == 0) {

                debug_msg("EmbeddedSID for this host is valid");
                return 0;
        }

        return 1;
}

/* 
 * remove session from hashtable and dealloca resources
 * when there will be an event 
 */
void clean_session_when_expired_cb(int sock, short which, void *arg) 
{
        extern http_proxy_core_t *proxy_core;
        const char * key = (const char*)arg;

        debug_msg("Session for key = '%s' expired", key);

        ht_remove(proxy_core->SIDs, key); 
}


