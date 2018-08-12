/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "mod_security.h"
#include "log.h"

/* Security Headers */

static void add_headers_for_uri(struct evkeyvalq *headers, cJSON * uri)
{
        cJSON *header = NULL;
        
        if(uri == NULL)
                return;

        if(headers == NULL)
                return;

        header = uri->child;
        
        while(header) {
                
                if(cJSON_IsString(header)) {
                        evhttp_remove_header(headers, header->string);
                        evhttp_add_header(headers, header->string, header->valuestring);
                }
                        
                header = header->next;
        }
}

/* Addition the security headers to response proxy->browser*/
void add_security_headers_to_response(req_proxy_to_server_t *proxy_req)
{
        extern http_proxy_core_t *proxy_core;
        cJSON *uri = NULL;
        const char *path;

        if(proxy_req == NULL)
                return;
        if(proxy_req->uri == NULL)
                return;

        if(proxy_core == NULL)
                return;
        
        if(proxy_core->json_security_headers == NULL)
                return;

        if((path = evhttp_uri_get_path(proxy_req->uri)) == NULL)
                path = "/";
        
        uri = cJSON_GetObjectItemCaseSensitive(proxy_core->json_security_headers, path);

        if(uri) {
                debug_msg("URI with path: '%s' in json_file FOUND!", path);
                add_headers_for_uri(evhttp_request_get_output_headers(proxy_req->req_client_to_proxy), uri);
        }
        else {
                debug_msg("URI with path: '%s' in json_file NOT FOUND! A set of default headers will be applied ", path);
                uri = cJSON_GetObjectItemCaseSensitive(proxy_core->json_security_headers, "EMBEDI_DefaultPatternUrl");
                add_headers_for_uri(evhttp_request_get_output_headers(proxy_req->req_client_to_proxy), uri);
        }
}
