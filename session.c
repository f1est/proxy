/*
 * @author f1est 
 */
 
#include "session.h"
#include "transport.h"


#define EXTRA_RAND_BYTES 60
#define MAX_RANDOM_BYTES_LENGTH 256

/* 
 * generate pseudorandom 
 * return 0 on success, -1 on filure.
 */
static int get_random_bytes(void *data, size_t size)
{

        FILE *fp;
        size_t cnt = 0;
        fp = fopen("/dev/urandom", "r");
        
        if(!fp) {
                debug_msg("Couldn't open '%s'. Error: %s\n", "/dev/urandom", strerror(errno));
                return -1;
        }
        
        cnt = fread(data, 1, size, fp);

        if(cnt < size)
                debug_msg("Read not enough data. Only %zu bytes, but it should be %zu", cnt, size );

        fclose(fp);
        return 0;

/*
        size_t  read_bytes = 0;
        ssize_t n;
        int     fd = -1;
        struct  stat st;

        if(!device)
                device = "/dev/urandom";

        if(strncmp(device, "/dev/random", 11) != 0) {
                if(strncmp(device, "/dev/urandom", 12)) != 0) {
                        debug_msg("device can be only random number source devices");
                        return -1;
                }
        }

        fd = open(device, O_RDONLY);
        
        if (fd < 0) {
                debug_msg(" Couldn't read '%s'. Error: %s\n", device, strerror(errno));
                return -1;
        }
        
        // Does the file exist and is it a character device? 
        if (fstat(fd, &st) != 0 ||
# ifdef S_ISNAM
                !(S_ISNAM(st.st_mode) || S_ISCHR(st.st_mode))
# else
                !S_ISCHR(st.st_mode)
# endif
                ) {
                close(fd);
                return -1;
        }
        
        for (read_bytes = 0; read_bytes < size; read_bytes += (size_t) n) {
                n = read(fd, bytes + read_bytes, size - read_bytes);
                if (n <= 0) {
                        break;
                }
        }
        
        if (read_bytes < size) {
                debug_msg("Could not gather sufficient random data\n");
                close(fd);
                return -1;
        }

        close(fd);
        return 0;
*/      
}

static void bin_to_readable(const void *in, char *out, size_t size)
{
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        char tmp[] = "\0\0";
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len, i;
        
        OpenSSL_add_all_digests();
        
        md = EVP_sha256();
        
        if(!md) {
                debug_msg("Unknown message digest");
                return;
        }
        
        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
//        EVP_DigestUpdate(mdctx, in, sizeof(in));
        EVP_DigestUpdate(mdctx, in, strlen(in));
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_destroy(mdctx);
        for(i = 0; (i < md_len) && (strlen(out) < size); i++) {
                sprintf(tmp, "%02x", md_value[i]);
                strncat(out, tmp, 2);
        }
}

/* 
 * return hash for peer connection and User-agent header of client on success
 * return NULL on failure 
 * return value needs to be deallocated by the caller.
 */
const char *get_hash_of_client(req_proxy_to_server_t *proxy_req)
{
        EVP_MD_CTX *mdctx;
        const EVP_MD *md;
        char tmp[] = "\0\0";
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len, i;
        char *hash;
        char *address = NULL;
        ev_uint16_t port = 0;
        const char *user_agent;

        evhttp_connection_get_peer(evhttp_request_get_connection(proxy_req->req_client_to_proxy), &address ,&port);

        user_agent = evhttp_find_header(evhttp_request_get_input_headers(proxy_req->req_client_to_proxy), "User-Agent");
        
        if(!address || !user_agent)
                return NULL;

        if((hash = malloc(HASH_LENGTH)) == NULL)
                return NULL;
        
        memset(hash, '\0', HASH_LENGTH);

        OpenSSL_add_all_digests();
        
        md = EVP_sha1();
        
        if(!md) {
                debug_msg("Unknown message digest");
                return NULL;
        }
        
        mdctx = EVP_MD_CTX_create();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, address, strlen(address));
        EVP_DigestUpdate(mdctx, user_agent, strlen(user_agent));
        EVP_DigestFinal_ex(mdctx, md_value, &md_len);
        EVP_MD_CTX_destroy(mdctx);
        for(i = 0; (i < md_len) && (strlen(hash) < HASH_LENGTH-2); i++) {
                sprintf(tmp, "%02x", md_value[i]);
                strncat(hash, tmp, 2);
        }

debug_msg("!!!!!!!!!!!! hash = %s", hash);
        if(strlen(hash) > 0)
                return hash;
        return NULL;
}

/* 
 * create Session ID (cookie-value)
 * return value needs to be deallocated by the caller if necessary.
 * return SID-string on succes or NULL on failure 
 */ 
const char *session_create_id()
{
	unsigned char rbuf[MAX_RANDOM_BYTES_LENGTH + EXTRA_RAND_BYTES];
	char *outid = malloc(MAX_SID_LENGTH);

        if(!outid) return NULL;

        memset(outid, '\0', MAX_SID_LENGTH);
        
        if (get_random_bytes(rbuf, MAX_RANDOM_BYTES_LENGTH) != 0) {
		return NULL;
	}
	bin_to_readable(rbuf, outid, (MAX_SID_LENGTH) - 2);

        if(strlen(outid) > 0)
                return outid;
        else {
                free((void*)outid);
                return NULL;
        }
}


/*
 * create cookie-name
 * return cookie-name on success or NULL on failure
 */
const char *session_create_name()
{
        return DEFAULT_SID_NAME;
}

/* 
 * return 0 if header Cookie not exist 
 * return -1 if Cookie-header exist, but it have not SID. In this case,
 * will be send 403-reply and close connection/
 * return 1 if Cookie-header exist and it have SID
 */ 
int cookie_check(struct evhttp_request *req_client_to_proxy)
{
        extern http_proxy_core_t *proxy_core;

        /* check if Cookie-header not exist */
        if(!evhttp_find_header(evhttp_request_get_input_headers(req_client_to_proxy),"Cookie"))        
                return 0;
        
        /* check if SID not exist in Cookie-header */
        if(cookie_check_SID(req_client_to_proxy) == NULL)   
                return -1;
        
        return 1;      
}

/*
 * concatenate and return string of all pairs of cookies
 * return NULL on fail
 * return value needs to be deallocated by the caller. 
 * if @param cut_key not NULL, it will be cut
 */
const char *cookie_get_all_pairs_as_string(hashtable_t *hashtable, const char * cut_key)
{
#define SIZE_OF_STRING_ALL_ENTRIES 128
        char *str;
        entry_t *hashtable_entry = NULL;
        size_t size_str = SIZE_OF_STRING_ALL_ENTRIES;
        if(hashtable == NULL)
                return NULL;

        if((str = malloc(size_str)) == NULL)
                return NULL;

        memset(str, '\0', size_str);

        for(size_t i = 0; i < ht_get_size(hashtable); i++) {

                if((hashtable_entry = ht_get_entry_on_index(hashtable, i)) != NULL) {

                        size_t tmp_size = 0;
                        
                        /* cutting cut_key */
                        if(cut_key) {
                               tmp_size = strlen(cut_key);
                               if(strncmp(hashtable_entry->key, cut_key, tmp_size > 0 ? tmp_size : strlen(hashtable_entry->key)) == 0) {
                                       continue;
                               }
                        }

                        tmp_size = strlen(str) + 
                                        strlen(hashtable_entry->key) +
                                        strlen((char*)hashtable_entry->value) + 
                                        strlen(";") + strlen("=");

                        if(tmp_size > size_str) {
                                size_str += tmp_size;
                                str = realloc(str, size_str);
                        }

                        if((tmp_size = strlen(hashtable_entry->key)) == 0) {
                                free((void*)str);
                                return NULL;
                        }
                        
                        if(strlen(str) != 0)
                                strncat(str, "; ", 2);
                                
                        strncat(str, hashtable_entry->key, tmp_size);
                        
                        if((tmp_size = strlen((char *)hashtable_entry->value)) != 0) {
                                strncat(str, "=", 1);
                                strncat(str, (char *)hashtable_entry->value, tmp_size);
                        }
                }
        }

        return str;
}

/* 
 * check existence the SID in hashtable of SID's and 
 * check the validity it and to belong to IP-address and User-agent of client
 * return -1 on failure, 0 on success
 */
int check_valid_SID(req_proxy_to_server_t * proxy_req)
{
        extern http_proxy_core_t *proxy_core; 
        session_t *session;
        
        const char *SID_value;
        const char *hash;
        
        if(!proxy_core)
                return -1;

        if(!proxy_core->SIDs)
                return -1;

        if(!proxy_req)
                return -1;

        if(!proxy_req->cookies_tbl)
                return -1;
        
        if((SID_value = ht_get_value(proxy_req->cookies_tbl, DEFAULT_SID_NAME)) == NULL)
                return -1;
       
        if((hash = get_hash_of_client(proxy_req)) == NULL)
                return -1;

        if((session = ht_get_value(proxy_core->SIDs, hash)) == NULL) {
                if(hash)
                        free((void *) hash);
                return -1;
        }

        if(strlen(SID_value) > 0 &&
                strlen(SID_value) == strlen(session->SID) &&
                strncmp((SID_value), session->SID, strlen(session->SID)) == 0) {
                if(hash)
                        free((void *) hash);
                return 0;
        }

        if(hash)
                free((void *) hash);

        return 1;
}
