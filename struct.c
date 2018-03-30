/*
 * @author f1est 
 */
 
#include "struct.h"
#include "config.h"
#include "session.h"

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
                        
                        if(sess->base.clone)
                                new_sess->base.clone = sess->base.clone;

                        new_sess->expires = sess->expires;
                        
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
                                free(str->str);

                        str->str = NULL;
                        break;
                }

                case type_session:
                {
                        debug_msg("TODO: free all content for session_t ");

                        session_t *sess = (session_t *)this;    

                        sess->SID = NULL;
                        sess->expires = 0;

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

char *st_string_t_get_str(string_t * str)
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
        new_sess->base.clone = &fn_data_clone;
        new_sess->base.free_content = &fn_content_free;

        return new_sess;
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
