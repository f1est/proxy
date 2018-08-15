/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "struct.h"
#include "config.h"
#include "session.h"
#include "common.h"

void session_add_expires_event(session_t *session, const char *key) 
{
        extern struct event_base *base;
        struct timeval timeout;
        int expires_time = config_get_expires_of_cookie();

        if(session == NULL || key == NULL)
                return;
        
        if(expires_time == -1)
                expires_time = EXPIRES_OF_COOKIES;
        expires_time *= 60; /* transfer to seconds */
        
        timeout.tv_sec = expires_time;
        timeout.tv_usec = 0;

        session->cleanup = evtimer_new(base, clean_session_when_expired_cb, (void *)key);
        evtimer_add(session->cleanup, &timeout);
}

base_t *fn_data_clone(base_t *this)
{
        if(this == NULL)
                return NULL;

        switch(this->type) {
                case type_string:
                {
                        string_t *str = (string_t *)this;     
                        string_t *new_str = malloc(sizeof(string_t));
                        
                        if(new_str == NULL)
                                return NULL;

                        memset(new_str, 0, sizeof(string_t));

                        new_str->base.type = str->base.type;
                                
                        if(str->str)
                                new_str->str = strdup(str->str);
                        
                        if(str->base.clone)
                                new_str->base.clone = str->base.clone;
                        
                        if(str->base.free_content)
                                new_str->base.free_content = str->base.free_content;
                                
                        return (base_t*)new_str;
                }
                
                case type_session:
                {
                        session_t *sess = (session_t *)this;     
                        session_t *new_sess = malloc(sizeof(session_t));
                        
                        if(new_sess == NULL)
                                return NULL;

                        memset(new_sess, 0, sizeof(session_t));
                        
                        new_sess->base.type = sess->base.type;

                        if(sess->SID)
                                new_sess->SID = strdup(sess->SID);
                        
                        if(sess->expires_str)
                                new_sess->expires_str = strdup(sess->expires_str);

                        if(sess->base.clone)
                                new_sess->base.clone = sess->base.clone;

                        new_sess->expires.tv_sec = sess->expires.tv_sec;
                        new_sess->expires.tv_usec = sess->expires.tv_usec;
                        
                        if(sess->base.free_content)
                                new_sess->base.free_content = sess->base.free_content;

                        return (base_t*)new_sess;
                }

                default:
                        return NULL;
        }
}

void fn_content_free(base_t *this)
{
        if(this == NULL)
                return;

        switch(this->type) {
                case type_string:
                {
                        string_t *str = (string_t *)this;   

                        if(str->str)
                                free((void*)str->str);

                        str->str = NULL;
                        break;
                }

                case type_session:
                {
                        debug_msg("TODO: free all content for session_t ");

                        session_t *sess = (session_t *)this;    

                        sess->SID = NULL;

                        if(sess->expires_str)
                                free((void*)sess->expires_str);

                        sess->expires.tv_sec = 0;
                        sess->expires.tv_usec = 0;

                        if(sess->cleanup)
                                event_free(sess->cleanup);
                        sess->cleanup = NULL;

                        break;
                }

                default:
                        break;
        }
}

string_t *st_string_t_init_ptr()
{
        string_t *new_str = malloc(sizeof(string_t));

        if(new_str == NULL)
                return NULL;
        
        memset(new_str, 0, sizeof(string_t));

        new_str->base.type = type_string;
        new_str->str = NULL;
        new_str->base.clone = &fn_data_clone;
        new_str->base.free_content = &fn_content_free;

        return new_str;
}

void st_string_t_init(string_t *data, char * str)
{
        data->base.type = type_string;
        data->base.clone = &fn_data_clone;
        data->base.free_content = &fn_content_free;
        data->str = str;
}

const char *st_string_t_get_str(string_t * str)
{
        if(str)
                return str->str;
        return NULL;
}

session_t *st_session_t_init()
{
        session_t *new_sess = malloc(sizeof(session_t));

        if(new_sess == NULL)
                return NULL;
        
        memset(new_sess, 0, sizeof(session_t));

        new_sess->base.type = type_session;
        new_sess->SID = NULL;
        new_sess->cleanup = NULL;
        new_sess->expires_str = NULL;
        new_sess->expires.tv_sec = 0;
        new_sess->expires.tv_usec = 0;
        new_sess->base.clone = &fn_data_clone;
        new_sess->base.free_content = &fn_content_free;

        return new_sess;
}

/* return -1 on failure or 0 on success */
int st_session_t_add_expires_str(session_t *session, const char *expires_str)
{
        if(session == NULL)
                return -1;

        if(expires_str == NULL)
                return -1;
debug_msg("expires_str = %s", expires_str);
        if(strlen(expires_str) > 0) {

                if(session->expires_str != NULL) 
                        free((void*)expires_str);

                session->expires_str = strdup(expires_str);
debug_msg("session->expires_str = %s", session->expires_str);
                return 0;
        }

        return -1;
}

void st_data_free(base_t *this)
{
        if(this == NULL)
                return;

        if(this->free_content)
                this->free_content(this);

        free(this);
}

void st_print(base_t *this)
{
        if(this == NULL)
                return;

        switch(this->type) {
                case type_string:     
                {
                        string_t *str = (string_t *)this;    

                        if(str->str)
                                debug_msg("This struct is type_string. str = %s", str->str);
                        
                        break;
                }

                case type_session:
                {       
                        session_t *sess = (session_t *)this;    
                        
                        debug_msg("This struct is type_session. SID = %s", sess->SID);
                        
                        break;
                }

                default:
                        break;
        }
}
