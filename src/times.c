/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "times.h"
#include "log.h"

#include <time.h>
#include <sys/time.h>


static char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };


int get_http_cookie_expires_str(char *buf, size_t len, const time_t *t)
{
        struct tm tm;

        gmtime_r(t, &tm);

        /*
         * Netscape 3.x does not understand 4-digit years at all and
         * 2-digit years more than "37"
         */

        return evutil_snprintf(buf, len,
                        (tm.tm_year > 2037) ?
                        "%s, %02d %s %d %02d:%02d:%02d GMT":
                        "%s, %02d %s %02d %02d:%02d:%02d GMT",
                        week[tm.tm_wday],
                        tm.tm_mday,
                        months[tm.tm_mon],
                        (tm.tm_year > 2037) ? tm.tm_year : tm.tm_year % 100,
                        tm.tm_hour,
                        tm.tm_min,
                        tm.tm_sec);
}

