/*
 *  extra-light http proxy server, v0.22
 *
 *  Copyright (C) 2004,2005  Christophe Devine
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "liblog/log.h"
#include "base64.h"

#ifndef uint32
#define uint32 unsigned long int
#endif

#ifndef MIN
#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#endif /* MIN */
#define CR '\r'
#define LF '\n'
#define CRLF "\r\n"
#define VERSION "0.1"



struct thread_data
{
    int client_fd;
    FILE *logfile;
    uint32 auth_ip;
    uint32 netmask;
    uint32 client_ip;
    int connect;
};
struct sockaddr_in proxy_addr;
struct sockaddr_in client_addr;
struct thread_data td;
int proxy_port, proxy_fd;
char proxy_realm[64] = "vlhttp proxy";
char *proxy_auth = NULL;
char *sys_auth = NULL;
int foreground_mode = 0;

int client_thread( struct thread_data *td );
char *request = NULL;
struct req_t
{
    char method[32];
    char http_ver[16];
    char url[1024];
    char headers[2048];
    char hostname[1024];
    int  port;
    char scheme[16];
    char url_host[256];
    char url_path[1024];
    char url_port[1024];
};
struct req_t req;

int init_proxy()
{
    /* create a new session */
    int n;

    if (!foreground_mode) {
        if( setsid() < 0 ) {
            ERR("setsid() fail", 0);
            return 0;
        }

        /* close all file descriptors */

        for( n = 0; n < 1024; n++ ) {
            close( n );
        }
    }

    td.logfile = NULL;

    /* create a socket */

    proxy_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

    if( proxy_fd < 0 ) {
        ERR("socket fail()", 0);
        return 0;
    }

    /* bind the proxy on the local port and listen */

    n = 1;

    if( setsockopt( proxy_fd, SOL_SOCKET, SO_REUSEADDR,
                    (void *) &n, sizeof( n ) ) < 0 )
    {
        ERR("setsockopt() fail", 0);
        return 0;
    }

    proxy_addr.sin_family      = AF_INET;
    proxy_addr.sin_port        = htons( (unsigned short) proxy_port );
    proxy_addr.sin_addr.s_addr = INADDR_ANY;

    if( bind( proxy_fd, (struct sockaddr *) &proxy_addr,
              sizeof( proxy_addr ) ) < 0 )
    {
        ERR("bind() fail()", 0);
        return 0;
    }

    if( listen( proxy_fd, 10 ) != 0 ) {
        ERR("listen() fail", 0);
        return 0;
    }
    return 1;
}

int main( int argc, char *argv[] )
{
    int pid;


    /* read the arguments */
    td.connect = 1;
    td.logfile = NULL;
	LOG_INIT(NULL);//"/tmp/vlhttp-debug.log");
    LOG_SET_LEVEL(LOG_LEVEL_DBG);
    char opt;
    while((opt = getopt(argc, argv, "p:i:m:r:A:S:f")) != -1) {
        switch(opt) {
            case 'A':
                encode_base64(optarg, strlen(optarg), (unsigned char**)(&proxy_auth));
                DBG("proxy_auth: %s", proxy_auth);
                break;
            case 'S':
                encode_base64(optarg, strlen(optarg), (unsigned char**)(&sys_auth));
                DBG("sys_auth: %s", sys_auth);
                break;
            case 'r':
                strncpy(proxy_realm, optarg, sizeof(proxy_realm));
                break;
            case 'p':
                proxy_port = atoi(optarg);
                break;
            case 'i':
                td.auth_ip = inet_addr(optarg);
                break;
            case 'm':
                td.netmask = inet_addr(optarg);
                break;
            case 'f':
                DBG("turn off daemon", 0);
                foreground_mode = 1;
                break;
        }
    }

    td.auth_ip &= td.netmask;
    td.client_ip = 0;

	DBG("========================================================================================================", 0);

    /* is inetd mode enabled ? */

    if( proxy_port == 0 )
    {
		int r;
        td.client_fd = 0; /* stdin */

		DBG("start",0);
		r = client_thread( &td );
		DBG("exit with %d code", r);

        return( r );
    }

    /* fork into background */
    if (!foreground_mode) {
        if ( (pid = fork() ) < 0 ) {
            ERR("fork() fail", 0);
            return -1;
        }
        if (pid) return ( 0 );
    }


    if (!init_proxy()) {
        return -1;
    }

    while( 1 )
    {
        int n = sizeof( client_addr );

        /* wait for inboud connections */

        if( ( td.client_fd = accept( proxy_fd,
                (struct sockaddr *) &client_addr, (socklen_t*)&n ) ) < 0 )
        {
            ERR("accept() fail", 0);
            return -1;
        }

        td.client_ip = client_addr.sin_addr.s_addr;

        /* verify that the client is authorized */

        if( ( td.client_ip & td.netmask ) != td.auth_ip )
        {
            close( td.client_fd );
            continue;
        }

        /* fork a child to handle the connection */
        if( ( pid = fork() ) < 0 )
        {
            close( td.client_fd );
            continue;
        }

        if( pid )
        {
            /* in father; wait for the child to terminate */

            close( td.client_fd );
            waitpid( pid, NULL, 0 );
            continue;
        }

        /* in child; fork & exit so that father becomes init */

        if( ( pid = fork() ) < 0 )
        {
            ERR("fork() fail", 0);
            return -1;
        }

        if( pid ) return ( 0 );

        return( client_thread( &td ) );

    }

    /* not reached */

    return -1;
}

void bad_request(struct thread_data *td )
{
	char message[]="<html><body><h1>Bad request</h1></body><html>";
    ssize_t writed;

	DBG("write: '%s'", message);
	writed = write( td->client_fd, message, sizeof(message));
}

void common_unauthorized(struct thread_data *td, int code)
{
	char buf[1024], *pstr = buf;
    ssize_t writed;

    pstr += snprintf(pstr, sizeof(buf), "HTTP/1.0 %d %sAuthentication Required\r\nServer: vlhttp"VERSION"\r\n", code, code == 407 ? "Proxy " : "" );
    pstr += snprintf(pstr, sizeof(buf), "%sAuthenticate: Basic realm=\"%s\"\r\n", code == 407 ? "Proxy-" : "", proxy_realm);
    pstr += snprintf(pstr, sizeof(buf), "\r\n\r\n<html><body><h1>ACCESS DENIED</h1><hr>proxy: vlhttp "VERSION"</body></html>\r\n");

	DBG("SEND TO CLIENT: '%s'", buf);
	writed = write( td->client_fd, buf, strlen(buf));
}
void proxy_unauthorized(struct thread_data *td )
{
    common_unauthorized(td, 407);
}
void sys_unauthorized(struct thread_data *td )
{
    common_unauthorized(td, 401);
}

char *get_header(const char *header)
{
	char *s;
	char headname[256];
	char *result = NULL;
	char *start = NULL, *end = NULL;

	snprintf(headname, sizeof(headname), "\n%s: ", header);
	s = strstr(req.headers, headname);
	if (s) {
		start = s + strlen(headname); 
		if ( (end = strchr(start, '\r')) || (end = strchr(start, '\n'))) 
			result = strndup(start, end-start);
	}

	if ( result ) {
		DBG("- HEADER found '%s': %s", header, result);
	} else {
		DBG("- HEADER '%s' not found", header);
	}

	return result;
}

int remove_header(const char *header)
{
	char *s;
	char headname[256];
	int result = 0;
	char *next_header = NULL, *end = NULL;
    char *end_of_headers = strstr(req.headers, "\r\n\r\n");

    if (!end_of_headers)
        goto end;

	snprintf(headname, sizeof(headname)-1, "\n%s: ", header);
	s = strstr(req.headers, headname);
	if (s) {
        s++;                                        // cut first \n
        if (!(end = strstr(s, "\r\n")))     // get next header
            goto end;                               // bad header!
        next_header = end + 2;
        memmove(s, next_header, strlen(next_header)+1);

        // cleanup tail
        //memset(&req.headers[strlen(req.headers)+1], 0, sizeof(req.headers) - strlen(req.headers)); 

        result = 1;
	}

	if ( result ) {
		//DBG("- HEADER removed '%s'", req.headers);
	} else {
		//DBG("- HEADER '%s' not found", req.headers);
	}

end:
	return result;
}

int add_header(const char* name, const char* value)
{
	char *s;
	int result = 0;
    char *end_of_headers = strstr(req.headers, "\r\n\r\n");
    if (!end_of_headers)
        goto end;

    // check room
    if ( (sizeof(req.headers) - strlen(req.headers) - strlen(name) - strlen(value) - 10) <= 0)
        goto end;

    s = end_of_headers + 2;                 // to end of last header
    sprintf(s, "%s: %s\r\n\r\n", name, value);
    result = 1;
end:
    return result;
}

int parse_hostname()
{
    char *host = get_header("Host");
    char *colon;
    
    if (!host) {
        host = strdup(req.url_host);
    }
    if (!host)
        return 0;

    if ( (colon = strchr(host, ':'))) {
        colon[0] = '\0';
    }
    strncpy(req.hostname, host, sizeof(req.hostname)-1);
    free(host);

    return 1;
}
int parse_request()
{
    int result = 0;
    if ( sscanf(request, "%31s %1023s %15s", req.method, req.url, req.http_ver) != 3) {
        ERR("sscanf() fail", 0);
        goto end;
    };
	DBG("-  method: '%s'", req.method);
	DBG("-  url: '%s'", req.url);
	DBG("-  http_ver: '%s'", req.http_ver);
    
    char *headers = strstr(request, "\r\n");
    char *end_of_req = strstr(headers, "\r\n\r\n");

    if (!end_of_req) {
        ERR("CRLFCRLF does not found", 0);
        goto end;
    }
    end_of_req[4] = '\0'; // terminate request by 0 char

    if (headers) {
        strncpy(req.headers, headers, sizeof(req.headers)-1);
        DBG("-  headers: '%s'", req.headers);
    }

    req.port = 80;

    if (sscanf(req.url, "%[^:]://%[^/]%[^\r\n]", req.scheme, req.url_host, req.url_path) < 2) {
        ERR("sscanf() fail", 0);
        goto end;
    }

    char *colon;
    if ((colon = strchr(req.url_host, ':'))) {
        colon++;
        req.port = atoi(colon);
        if ( req.port <= 0 ) {
            ERR("bad port %d", req.port);
            goto end;
        }
    }

    if (!parse_hostname()) {
        ERR("parse_hostname() fail", 0);
        goto end;
    }
    result = 1;
	DBG("-  req.scheme: '%s'", req.scheme);
	DBG("-  req.url_host: '%s'", req.url_host);
	DBG("-  req.url_path: '%s'", req.url_path);
	DBG("-  req.port: '%d'", req.port);
	DBG("-  req.hostname: '%s'", req.hostname);
end:
    if (!result) {
        LOG_HEXDUMP("BAD REQUEST", (unsigned char*)request, strlen(request)+1);
    }
    return result;
}

int is_syscmd()
{
    if ( strcmp(req.hostname, "syscmd") == 0 ) {
        return 1;
    } else {
        return 0;
    }
}

int is_common_authorized(const char* header, const char* userpass64)
{
    char *req_auth = NULL;
    char req_scheme[32];
    char req_encoded[32];
    int result = 0;
    char *reason = "unknown";

    if (!userpass64) {
        result = 1;
        goto exit;
    }

    req_auth = get_header(header);
    
    if (!req_auth) {
        reason = "header does not exists";
        goto exit;
    }

    if (sscanf(req_auth, "%31s %31s", req_scheme, req_encoded) < 2) {
        reason = "scanf fail";
        WARN("bad auth: %s", req_auth);
        goto exit;
    }

    if (strcmp(req_scheme, "Basic")) {
        WARN("bad auth scheme: %s", req_scheme);
        reason = "auth scheme does not supported";
        goto exit;
    }

    if (strcmp(req_encoded, userpass64) == 0) {
        result = 1;
    } else {
        reason = "user/pass invalid";
    }

exit:
    if (req_auth)
        free(req_auth);
    if (!result) {
        WARN("UNAUTHORIZED: %s", reason);
    } else {
        INFO("AUTHORIZED", 0);
    }
    return result;
}
int is_proxy_authorized()
{
    return is_common_authorized("Proxy-Authorization", proxy_auth);
}
int is_sys_authorized()
{
    // reject if sys auth is not set
    if (!sys_auth)
        return 0;
    return is_common_authorized("Authorization", sys_auth);
}



int process_sys_cmd()
{
    // here reject too
    if (!sys_auth)
        return 0;
    //system(req.url);
    return 1;
}


int client_thread( struct thread_data *td )
{
    int remote_fd = -1;
    int state, method_connect=0;
    int n, client_fd;
	int result = -1;
    uint32 client_ip;
    ssize_t writed;
    int already_authorized = 0;

#define BUF_SIZE 1500
#define REQ_SIZE 15000
    char buffer[BUF_SIZE];
    char last_host[BUF_SIZE];
    request = malloc(REQ_SIZE);
    memset(&req, 0, sizeof(req));


    struct sockaddr_in remote_addr;
    struct hostent *remote_host;
    struct timeval timeout;

    fd_set rfds;

	FENTER;
	ASSERT(request);

    client_fd = td->client_fd;
    client_ip = td->client_ip;

    /* fetch the http request headers */
    FD_ZERO( &rfds );
    FD_SET( (unsigned int) client_fd, &rfds );

    timeout.tv_sec  = 15;
    timeout.tv_usec =  0;

    if ( select(client_fd + 1, &rfds, NULL, NULL, &timeout ) <= 0) {
		ERR("select() timeout", 0);
		result = 11;
        goto exit;
    }
        
    char *end_of_req = NULL;
    char *preq = request;
	memset(buffer, 0, BUF_SIZE);
    if ( ( n = read(client_fd, buffer, sizeof(buffer)-4) ) <= 0 ) {
        ERR("read() fail", 0);
        result = 12;
        goto exit;
    }
    DBG("-  recv %d bytes", n);
    // append
    preq += snprintf(preq, REQ_SIZE-(preq-request-2), "%s", buffer);

process_request:
    while ( !(end_of_req = strstr(request, "\r\n\r\n")) ) {
        DBG("-  request without %s", ANSI_WHITE"CRLFCRLF"ANSI_RESET);
        if ( ( n = read(client_fd, buffer, sizeof(buffer)-4) ) <= 0 ) {
            ERR("read() fail", 0);
            result = 12;
            goto exit;
        }
        DBG("-  recv %d bytes", n);
        // append
        preq += snprintf(preq, REQ_SIZE-(preq-request-2), "%s", buffer);
    }
    end_of_req[4] = '\0';

//#define DUMP
#ifdef DUMP
    LOG_HEXDUMP("RECEIVED FROM CLIENT", (unsigned char*)request, preq-request);
#else
    DBG("RECEIVED FROM CLIENT %d bytes", preq-request);
#endif
    if (!parse_request()) {
        WARN("bad request:", request);
        return -1;
    };

    if (!already_authorized) { 
        if (is_proxy_authorized()) {
            already_authorized = 1;
        } else {
            proxy_unauthorized(td);
            goto exit;
        }
    }

    if ( is_syscmd() ) {
        if ( is_sys_authorized() ) {
            process_sys_cmd();
            goto exit;
        } else {
            sys_unauthorized(td);
            goto exit;
        }
    }


    //LOG_HEXDUMP("BEFORE", (unsigned char*)req.headers, BUF_SIZE);
    remove_header("Proxy-Authorization");
    remove_header("Proxy-Connection");
    //LOG_HEXDUMP("AFTER", (unsigned char*)req.headers, BUF_SIZE);

    /* resolve the http server hostname */
    if( !(req.hostname) || !( remote_host = gethostbyname( req.hostname ) ) ) {
		WARN("-  fail to resolve '%s'", req.hostname);
        result = 19;
		goto exit;
    }

#if 0
    if( method_connect )
    {
        if( td->connect == 1 && req.port != 443 )
        {
            result = 20;
			goto exit;
        }
    }
#endif

    /* connect to the remote server, if not already connected */
    if ( strcmp(req.hostname, last_host) ) {
        shutdown( remote_fd, 2 );
        close( remote_fd );

        remote_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );

        if (remote_fd < 0) {
			WARN("-  socket() fail", 0);
            result = 21;
			goto exit;
        }

        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons( (unsigned short) req.port );

        memcpy( (void *) &remote_addr.sin_addr,
                (void *) remote_host->h_addr,
                remote_host->h_length );

        if ( connect( remote_fd, (struct sockaddr *) &remote_addr, sizeof( remote_addr ) ) < 0 ) {
			WARN("-  connect() to '%s:%d' fail", req.hostname, req.port);
            result = 22;
            goto exit;
        }
        DBG("-  connected to %s:%d", req.url_host, req.port);

        memset( last_host, 0, sizeof( last_host ) );
        strncpy( last_host, req.hostname, sizeof( last_host ) - 1 );
    } else {
        INFO("reuse current connection", 0);
    }

#if 0
    if( method_connect )
    {
        /* send HTTP/1.0 200 OK */

        buffer[0] = 'H'; buffer[ 7] = '0'; buffer[14] = 'K';
        buffer[1] = 'T'; buffer[ 8] = ' '; buffer[15] = '\r';
        buffer[2] = 'T'; buffer[ 9] = '2'; buffer[16] = '\n';
        buffer[3] = 'P'; buffer[10] = '0'; buffer[17] = '\r';
        buffer[4] = '/'; buffer[11] = '0'; buffer[18] = '\n';
        buffer[5] = '1'; buffer[12] = ' ';
        buffer[6] = '.'; buffer[13] = 'O';

        if( write( client_fd, buffer, 19, 0 ) != 19 )
        {
            result = 23;
			goto exit;
        }
    }
    else
#endif
    {
		n = snprintf(buffer, BUF_SIZE, "%s %s %s%s", req.method, req.url, req.http_ver, req.headers); 
        if ((writed = write(remote_fd, buffer, n)) != n ) {
            WARN("write() fail: %d", writed);
            result = 24;
			goto exit;
        }
#ifdef DUMP
		LOG_HEXDUMP("SENDED TO SERVER", (unsigned char*)buffer, BUF_SIZE);
        DBG("-  size %d+%d+%d+%d+2=%d", strlen(req.method), strlen(req.url), strlen(req.http_ver), strlen(req.headers), strlen(req.method) + strlen(req.url) + strlen(req.http_ver) + strlen(req.headers) + 2 );
        DBG("-  sended to server %d(0x%x) of %d(0x%x) bytes", writed, writed, n, n);
#else
        DBG("SENDED TO SERVER %d bytes", n);
#endif
    }

    /* tunnel the data between the client and the server */

    state = 0;

    while( 1 )
    {
        FD_ZERO( &rfds );
        FD_SET( (unsigned int) client_fd, &rfds );
        FD_SET( (unsigned int) remote_fd, &rfds );
    
        n = ( client_fd > remote_fd ) ? client_fd : remote_fd;

        if ( select( n + 1, &rfds, NULL, NULL, NULL ) < 0 ) {
            ERR("select() fail", 0);
            result = 25;
			goto exit;
        }

        if ( FD_ISSET( remote_fd, &rfds ) ) {
            if ( ( n = read( remote_fd, buffer, BUF_SIZE-1) ) <= 0 ) {
                WARN("read() fail: %d", n);
                result = 26;
				goto exit;
            }
#ifdef DUMP
			LOG_HEXDUMP("RECEIVED FROM SERVER (tunneled)", (unsigned char*)buffer, n);
#else
            DBG("RECEIVED FROM SERVER (tunneled) %d bytes", n);
#endif

            state = 1; /* client finished sending data */

            if ( (writed = write( client_fd, buffer, n )) != n ) {
                WARN("write() fail: %d", writed);
                result = 27;
				goto exit;
            }
#ifdef DUMP
			LOG_HEXDUMP("SENDED TO CLIENT (tunneled)", (unsigned char*)buffer, n);
#else
            DBG("SENDED TO CLIENT (tunneled) %d bytes", n);
#endif
        }

        if ( FD_ISSET( client_fd, &rfds ) ) {
            if ( (n = read( client_fd, buffer, BUF_SIZE-1)) <= 0 ) {
                WARN("read() fail: %d", n);
                result = 28;
				goto exit;
            }
#ifdef DUMP
			LOG_HEXDUMP("RECEIVED FROM CLIENT (tunneled)", (unsigned char*)buffer, n);
#else
            DBG("RECEIVED FROM CLIENT (tunneled) %d bytes", n);
#endif

            if ( state && !method_connect ) {
                /* new http request */
                WARN("NEW HTTP REQ", 0);
                int req_len = MIN((size_t)n, REQ_SIZE-1);
                strncpy(request, buffer, req_len);
                preq = request + req_len;
                goto process_request;
            }

            if ((writed = write( remote_fd, buffer, n)) != n ) {
                WARN("write() fail: %d", writed);
                result = 29;
				goto exit;
            }
#ifdef DUMP
			LOG_HEXDUMP("SENDED TO SERVER (tunneled)", (unsigned char*)buffer, n);
#else
            DBG("SENDED TO SERVER (tunneled) %d bytes", n);
#endif
        }
    }


    /* not reached */
exit:

    shutdown( client_fd, 2 );
    shutdown( remote_fd, 2 );
    close( client_fd );
    close( remote_fd );
	if (request) free(request);
	FLEAVEA("exit with %d code", result);
    return( result );
}


#if 0
    method_connect = 0;
    if( buffer[0] == 'C' && buffer[4] == 'E' &&
        buffer[1] == 'O' && buffer[5] == 'C' &&
        buffer[2] == 'N' && buffer[6] == 'T' &&
        buffer[3] == 'N' && buffer[7] == ' ' )
    {
        if( ! td->connect )
        {
            result = 13;
        }

        method_connect = 1;
    }
#endif

#if 0
	/* Parse headers */
	snprintf(headers, BUF_SIZE, "%s", white_space);
	DBG("-  headers: '%s'", headers);
	http11_host = get_header("Host", headers);

	/* Parse HTTP host and request*/
    url_host = url;
	if (strncmp(url, "http://", 7) == 0 ) {

		snprintf(scheme, sizeof(scheme), "http://");

		/* Parse HTTP request */
		pstr = url+7; /* 7 - is a strlen("http://") */
		while ( pstr[0] && pstr[0] != ':' && pstr[0] != '/' && pstr[0] != ' ' && pstr[0] != CR )
			pstr++;

		if (pstr == url+7) {
			snprintf(url_req, BUF_SIZE, "/");
			snprintf(url_host, BUF_SIZE, "%s", url);
		} else if (pstr) {
			snprintf(url_req, BUF_SIZE, "%s", pstr);
			snprintf(url_host, MIN(BUF_SIZE, (unsigned int)(pstr-(url+7))+1), "%s", url+7);

			while ( pstr[0] && pstr[0] != ':' && pstr[0] != '/' && pstr[0] != ' ' && pstr[0] != CR )
				pstr++;
			ASSERT(pstr);
	
		} else {
			ASSERT(pstr);
			result = 17;
			goto exit;
		}

		DBG("-  url_req: '%s'", url_req);
		DBG("-  url_host: '%s'", url_host);
		if ( http11_host ) {
			snprintf(url_host, BUF_SIZE, "%s", http11_host);
			DBG("-  url_host changed to: '%s'", url_host);
		}

	} else {
		bad_request(td);
		result = 18;
		goto exit;
	}

	pstr = strchr(url_host, ':');
	if ( pstr ) {
		snprintf(host, MIN(sizeof(host), (unsigned int) (pstr-url_host)), "%s", url_host);
		url_port = pstr;
		if ((!url_port) || (!atoi(url_port))) {
			WARN("Bad port: '%s'", url_port);
			url_port = "80";
		}
	} else { 
		url_port = "80";
		snprintf(host, sizeof(host), "%s", url_host);
	}

	DBG("-  host: '%s'", host);
	DBG("-  url_port: '%s'", url_port);




#endif
