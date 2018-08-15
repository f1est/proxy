/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef MOD_SECURITY_H
#define MOD_SECURITY_H

#include "transport.h"
#include "common.h"
#include "cJSON.h"

/* Security Headers */

/* Addition the security headers to response proxy->browser*/
void add_security_headers_to_response(req_proxy_to_server_t *proxy_req);

#endif /* MOD_SECURITY_H */
