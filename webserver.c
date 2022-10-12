/*
 * webserver.c - Simple Web server (serves only files)
 *
 * TEAM MEMBERS:
 *     Kayleah Tsai, ktsai@hmc.edu
 *     Eric Chen, erchen@hmc.edu
 */ 

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>

/*
 * Fill in the following with your CS login IDs.
 */
const char *team = "ktsai+erchen";

/* The name of the server's log file */
#define SERVER_LOG      "server.log"

/* Maximum socket queue */
#define LISTEN_MAX      10

/* 
 * Maximum length of a pathname in a GET request; also used as an initial
 * buffer size.  Should be a power of 2.
 */
#define MAXLINE         4096

/* 
 * Define this (#define) if you want debugging output; undefine it
 * (#undef) if you don't.  It is up to you to decide where to add
 * debugging output, although there a few examples in the supplied
 * code.
 */
#undef DEBUG
//#define DEBUG

/* 
 * This struct remembers some key attributes of an HTTP request and
 * the thread that is processing it.
 */
typedef struct {
    int myid;                       /* Thread ID for debug messages */
    int connfd;                     /* Connected file descriptor */ 
    union clientaddr {
        struct sockaddr_in client4;
        struct sockaddr_in6 client6;
    } clientaddr;                   /* Client IP address */
    socklen_t clientlen;            /* Length of client IP address */
} arglist_t;

/*
 * Global variables
 */ 
const char *progname;               /* Program name, for error messages */
FILE *log_file;                     /* Server log file */
char hostname[NI_MAXHOST];
char hostaddr[NI_MAXHOST];
int listenfd;
int error;
extern int errno;
static pthread_mutex_t  mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 * Place forward function declarations here.
 */
int open_listenfd(const char *port);
void *process_request(void* vargp);
char *read_request(arglist_t *args);
char *parse_uri(arglist_t *args, char *uri);
void write_log(arglist_t *args, const char *message, const char *data);
void http_error(arglist_t *args, int error_id);
void copy_to_client(arglist_t *args, char* request, char* path);
/*
 * Main program of the Web server.  After initialization, loops
 * forever waiting for connections and calling process_request to
 * handle them.
 */
int main(int argc, char *argv[])
{
    int request_counter = 0;
    arglist_t *args = NULL;   /* Argument structure passed to each thread */

    progname = argv[0];

    /* Check arguments */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port number>\n", progname);
        return 2;
    }

    /* 
     * Ignore any SIGPIPE signals elicited by writing to a connection
     * that has already been closed by the peer process.
     */
    signal(SIGPIPE, SIG_IGN);

    /*
     * Initialize socket and log file. 
     *
     */
    
    listenfd= open_listenfd(argv[1]);

    log_file = fopen(SERVER_LOG, "w");

    /*
     * Wait for and process client connections
     */
    while (1) { 
        pthread_t process_tid;

        args = calloc(1, sizeof(arglist_t));
        if (args == NULL) {
            fprintf(stderr, "%s: arglist allocation error\n", progname);
            return 1;
        }
            
        /*
         * Accept a connection and call process_request, either as a
         * function or as a thread.
         *
         */

         args->myid = request_counter;
         request_counter++;
         args ->clientlen = sizeof args->clientaddr;
         args->connfd = accept(listenfd, (struct sockaddr *)& args->clientaddr, &args->clientlen);
         if(args->connfd == -1){
            if (pthread_mutex_lock(&mutex)!=0){
                fprintf(stderr, "Mutex lock failed.");
            }
            write_log(args, "connection failed", strerror(errno));
            if (pthread_mutex_unlock(&mutex)!=0){
                fprintf(stderr, "Mutex unlock failed.");
            }
             continue;
         }
         error = getnameinfo((struct sockaddr*)& args->clientaddr, args->clientlen, hostname, sizeof hostname, NULL, 0, 0);

        if (error != 0) {
            fprintf(stderr, "Couldn't get name info for client: %s\n",
            gai_strerror(error));
            if (pthread_mutex_lock(&mutex)!=0){
                fprintf(stderr, "Mutex lock failed.");
            }
            write_log(args, "Counldn't get name info for client", gai_strerror(error));
            if (pthread_mutex_unlock(&mutex)!=0){
                fprintf(stderr, "Mutex unlock failed.");
            }
            close(args->connfd);
            continue;
        }
        error = getnameinfo((struct sockaddr*)& args->clientaddr, args->clientlen,
        hostaddr, sizeof hostaddr, NULL, 0, NI_NUMERICHOST);
        if (error != 0) {
            fprintf(stderr, "Couldn't get numeric info for client %s: %s\n",
            hostname, gai_strerror(error));
            if (pthread_mutex_lock(&mutex)!=0){
                fprintf(stderr, "Mutex lock failed.");
            }
            write_log(args, "Counldn't get numeric info for client", gai_strerror(error));
            if (pthread_mutex_unlock(&mutex)!=0){
                fprintf(stderr, "Mutex unlock failed.");
            }
            close(args->connfd);
            continue;
        }
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }

        // create a thread
        if(pthread_create(&process_tid, NULL, process_request, args)){
            fprintf(stderr, "Couldn't create process thread\n");
            return 1;
         }
        }

    /* Control never reaches here */
    return 0;
}

/*
 * The following function is taken pretty much verbatim from the echo server.
 */
int open_listenfd(const char *port)
{
    int listenfd;                       /* FD we will return to our caller */
    int optval = 1;                     /* Socket option value we will set */
    struct addrinfo hints;              /* Hints needed by getaddrinfo */
    struct addrinfo *hostaddresses;     /* Where getaddrinfo returns data */
    int error;                          /* Result of getaddrinfo */

    /* Find out our IP address, and set our port */
    memset(&hints, 0, sizeof hints);
    hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED | AI_PASSIVE;
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(NULL, port, &hints, &hostaddresses);
    if (error != 0) {
	freeaddrinfo(hostaddresses);
	fprintf(stderr, "port %s: %s\n", port, gai_strerror(error));
	/*
	 * Since we already printed the error, set errno to zero to prevent
	 * bogus messages, and return -2 to indicate that we printed.
	 */
	return -2;
    }

    /* Create a socket descriptor */
    /* We take advantage of the fact that AF_* and PF_* are identical */
    listenfd = socket(hostaddresses->ai_family,
      hostaddresses->ai_socktype, hostaddresses->ai_protocol);
    if (listenfd == -1) {
	freeaddrinfo(hostaddresses);
        return -1;
    }

    /* Eliminate "Address already in use" errors from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *)&optval , sizeof optval) == -1) {
        freeaddrinfo(hostaddresses);
        return -1;
    }

    /*
     * Listenfd will be an endpoint for all requests to the port
     * on any IP address for this host.
     */
    if (bind(listenfd, hostaddresses->ai_addr, hostaddresses->ai_addrlen)
      == -1) {
	freeaddrinfo(hostaddresses);
        return -1;
    }

    /*
     * Make it a listening socket ready to accept connection requests.
     */
    freeaddrinfo(hostaddresses);
    if (listen(listenfd, LISTEN_MAX) == -1)
        return -1;

    return listenfd;
}

/*
 * process_request: Handle a single HTTP request from a client.
 *
 * In its simplest form, process_request is called directly as a
 * function from the main program.  That produces a Web server that
 * can handle only one client at a time.
 *
 * In the more advanced form, process_request is called as a thread.
 * In that case, the server can handle multiple simultaneous clients.
 *
 * The general outline of the function is as follows:
 *
 * 1. If threaded, detach so that the main function doesn't have to ever
 *    call pthread_join.
 * 2. Read the HTTP request from a client, including headers.
 * 3. Parse the HTTP request to extract the name of the file that should
 *    be sent.
 * 4. Open the file and copy it to the client.
 * 5. Close the file, close the socket we used to talk to it, and exit.
 *
 * Since this is (potentially) a thread function, process_request is
 * required to have a return value.  For our purposes, it can (and
 * should) always return NULL.
 */ 
void *process_request(void *vargp) 
{
    arglist_t *args;                /* Arguments passed to thread */ 
    char *pathname;                 /* Pathname extracted from GET request */
    char *request;                  /* Buffer that will hold entire request */
    char *lineend;
    char *firstline;

    args = (arglist_t *)vargp;      /* Make friendlier pointer to arguments */

    /*
     * 1 to detach the thread, 0 for unthreaded server.
     *
     */
#if 1
    if (pthread_detach(pthread_self()) == -1) {
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        write_log(args, "pthread_detach failed:", strerror(errno));
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }
        free(args);
        return NULL;
    }
#endif /* 1 */

    /*
     * Read the request from the client.
     */
    request = read_request(args);

    /*
     * If the request was no good, we'll get a NULL pointer.  In that
     * case we need to clean up, which means closing the connection
     * and freeing the args struct.
     *
     */
    if (request == NULL) {
        http_error(args, 400);
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        write_log(args, "bad request", NULL);
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }
        close(args->connfd);
        free(args);
        return NULL;                /* read_request gave an error message */
    }
    
#ifdef DEBUG
    fprintf(stderr, "Thread %d got full request %s", args->myid, request);
#endif /* DEBUG */

    /*
     * Use parse_uri to extract the pathname from the request.
     */
    pathname = parse_uri(args, request);
    /*
     * error handling
     */
    if (pathname == NULL) {
        http_error(args, 400);
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        write_log(args, "Bad Request; Null pathname", NULL);
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }
        close(args->connfd);
        free(request);
        free(args);
        return NULL;                /* parse_uri gave an error message */
    }

    /*
     * Check for simple hacking attempts.
     *
     * DO NOT REMOVE THIS CODE!
     */
    if (strstr(pathname, "../") != 0) {
        /*
         * The client is trying to access forbidden files.  Disallow it!
         */
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        write_log(args, "Breakin attempt!", request);
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }
        http_error(args, 403);
        free(request);
        free(pathname);
        close(args->connfd);
        free(args);
        return NULL;
    }

    /*
     * Log the first line of the request.
     *
     */
    lineend = strchr(request, '\n');
    firstline = malloc(lineend-request+1);
    firstline = strncpy(firstline, request, lineend-request);
    
    if (pthread_mutex_lock(&mutex)!=0){
        fprintf(stderr, "Mutex lock failed.");
    }
    write_log(args, firstline, NULL);
    if (pthread_mutex_unlock(&mutex)!=0){
        fprintf(stderr, "Mutex unlock failed.");
    } 
    /*
     * Open the requested file and send it to the client.
     * 
     */
    copy_to_client(args, request, pathname);
    close(args->connfd);
    free(args);
    return NULL;
}

/*
 * Read bytes from the client until a blank line is seen.  Return a
 * malloc'ed buffer containing those bytes; the caller is responsible
 * for freeing it.
 *
 * The buffer is terminated by a NUL byte ('\0') following the blank line.
 *
 * If an error occurs, logs a message and returns NULL.
 *
 * BUG: We assume that there is nothing following the blank line.  If
 * there is, we may swallow (and discard) important data.  Thus, this
 * function is broken for clients that expect HTTP/1.1 and HTTP/2.0.
 */
char *read_request(arglist_t *args)
{
    char *buffer = malloc(MAXLINE);     /* Buffer holding request */
    char *searchstart;                  /* Where to search from */
    char *found;                        /* String that was found */
    size_t bufmax = MAXLINE;            /* Current maximum size of buffer */
    size_t bufsize = 0;                 /* Current size of data in buffer */
    size_t nbytes;                      /* Number of bytes read from socket */

    if (buffer == NULL) {
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        write_log(args, "read_request couldn't allocate memory", NULL);
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }
        return NULL;
    }
    while (1) {
        /*
         * Read request from connection and handle errors.  Terminate
         * request with a NUL byte.
         */
        nbytes = read(args->connfd, &buffer[bufsize], bufmax - bufsize - 1);

        if (nbytes == 0) {
            buffer[bufsize] = '\0';
            return buffer;
        }
        else if (nbytes == -1) {
            if (pthread_mutex_lock(&mutex)!=0){
                fprintf(stderr, "Mutex lock failed.");
            }
            write_log(args, "read failed:", strerror(errno));
            if (pthread_mutex_unlock(&mutex)!=0){
                fprintf(stderr, "Mutex unlock failed.");
            }
            free(buffer);
            return NULL;
        }
        buffer[bufsize + nbytes] = '\0';

        /*
         * Look inside the buffer for a blank line (\n\n or \r\n\r\n).
         * For efficiency, we start the search just before the data we
         * just read, rather than at the beginning of the buffer.
         */
        if (bufsize > 1)
            searchstart = buffer + bufsize - 2;
        else
            searchstart = buffer;
        found = strstr(searchstart, "\n\n");
        if (found != NULL) {
            found[2] = '\0';            /* Found blank line, put NUL after it */
            return buffer;
        }
        found = strstr(searchstart, "\r\n\r\n");
        if (found != NULL) {
            found[4] = '\0';            /* Found blank line, put NUL after it */
            return buffer;
        }

        /*
         * At this point we have read some data but haven't found a blank
         * line.  If the remaining space in the buffer is limited, grow
         * the buffer by a factor of two so we have enough space to read
         * more stuff.
         */
        bufsize += nbytes;
        if (bufmax - bufsize < MAXLINE) {
            bufmax *= 2;
            buffer = realloc(buffer, bufmax);
            if (buffer == NULL) {
                if (pthread_mutex_lock(&mutex)!=0){
                    fprintf(stderr, "Mutex lock failed.");
                }
                write_log(args, "read_request couldn't reallocate memory",NULL);
                if (pthread_mutex_unlock(&mutex)!=0){
                    fprintf(stderr, "Mutex unlock failed.");
                }
                return NULL;
            }
        }        
    }
}

/*
 * Parse the contents of a request.  The request is passed as a single
 * string containing multiple lines, terminated by a blank line and a
 * NUL byte.  We only deal with the first line, which is the GET
 * request, and only extract the pathname from that request.
 *
 * Returns a malloc'ed buffer containing the pathname, or NULL if an
 * error occurs.  Errors produce a message in the log file.  The
 * caller is responsible for freeing the pathname buffer.
 */
char *parse_uri(arglist_t *args, char *request)
{
    char *path;                         /* Malloc'ed space for the path */
    char *pathbegin;                    /* Pointer to beginning of pathname */
    char *pathend;                      /* Pointer to end of pathname */
    char *protocol;                     /* Pointer to beginning of protocol */
    char *lineend;                      /* Pointer to end of first line */

    /*
     * Make sure we have a GET request.  We don't support POST, HEAD, etc.
     */
    if (strncmp(request, "GET ", 4) != 0) {
        /*
         * Not a GET request.
         */
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        write_log(args, "Non-GET request", request);
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }
        return NULL;
    }

    /*
     * The requested pathname starts at request + 4 and ends with a
     * blank.  Look for both the end of the path and the end of the
     * line. "/" at the start of the file is removed.
     *
     */
    
    pathbegin = request + 4;

    while(*pathbegin == ' '){
        pathbegin += 1;
    }
    if(*pathbegin == '/'){
        pathbegin += 1;
    }

    pathend = strchr(pathbegin, ' ');
    lineend = strchr(pathbegin, '\n');

    if (pathend == NULL || lineend == NULL || pathend >= lineend) {
        /*
         * Invalid GET format.
         */
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        write_log(args, "Invalid GET format", request);
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }
        return NULL;
    }
    protocol = pathend + 1;
    if (strncmp(protocol, "HTTP/1.0\r\n", lineend - protocol) != 0
      && strncmp(protocol, "HTTP/1.1\r\n", lineend - protocol) != 0
      && strncmp(protocol, "HTTP/2.0\r\n", lineend - protocol) != 0) {
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        write_log(args, "Invalid HTTP version", request);
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }
        return NULL;
    }

    /*
     * Allocate space to hold the path, copy it in,
     * and return it.  Don't forget space for the NUL byte!
     */
    path = malloc(pathend-pathbegin+1);
    strncpy(path, pathbegin, pathend-pathbegin);
    path[pathend-pathbegin] = '\0';


#ifdef DEBUG
    fprintf(stderr, "parse_uri found path '%s'\n", path);
#endif /* DEBUG */
    return path;
}


/*
 * Write a message to the log file.  The message can be composed of
 * either one or two strings.
 *
 * Note that as-is, this function is NOT thread-safe!
 */
void write_log(arglist_t *args, const char *message, const char *data)
{
    char clientname[NI_MAXHOST];        /* Space to hold client name */
    char clientaddr[NI_MAXHOST];        /* Space to hold client address */
    time_t now;                         /* Current time */
    char time_str[MAXLINE];             /* Space for holding current time */
    int error;                          /* Error code from getnameinfo */

    /*
     * Get a formatted time string
     */
    now = time(NULL);
    strftime(time_str, MAXLINE, "%D %T", localtime(&now));

    /*
     * Get the name and address of the client.
     */
    error = getnameinfo((struct sockaddr*)&args->clientaddr, args->clientlen,
      clientname, sizeof clientname, NULL, 0, 0);
    if (error != 0)
        strncpy(clientname, "UNKNOWN", sizeof clientname);
    error = getnameinfo((struct sockaddr*)&args->clientaddr, args->clientlen,
      clientaddr, sizeof clientaddr, NULL, 0, NI_NUMERICHOST);
    if (error != 0)
        strncpy(clientaddr, "0.0.0.0", sizeof clientaddr);

    /* 
     * Write the log message to the log file.
     *
     */
    if (data == NULL)
        fprintf(log_file, "%s thread %d %s(%s): %s\n", time_str, args->myid,
          clientname, clientaddr, message);
    else {
        fprintf(log_file, "%s thread %d %s(%s): %s %s", time_str, args->myid,
          clientname, clientaddr, message, data);
        if (data[strlen(data) - 1] != '\n')
            fputc('\n', log_file);
    }
    fflush(log_file);
}

/*
 * Function to issue HTTP error responses.  An HTTP error consists of
 * an error line that includes the error code and an English
 * translation of it, followed by zero or more optional header lines
 * and a blank line.  After the blank line there should be a brief Web
 * page giving the appropriate error message.
 *
 * This function also serves as an example of how to write a response
 * to the client.
 */
void http_error(arglist_t *args, int error_id)
{
    char buf[MAXLINE];          /* Buffer for formatting messages */
    char* message;              /* Message explaining error */
    int nbytes;                 /* Number of bytes written */

    /*
     * Figure out an error message.
     *
     */
    if (error_id == 400)
        message = "Bad request";
    else if (error_id == 403)
        message = "Forbidden";
    else if (error_id == 404)
        message = "Not found";
    else {
        error_id = 500;
        message = "Internal server error";
    }

    /*
     * Create a full response, including both headers and HTML, in buf.
     */
    nbytes = snprintf(buf, sizeof buf,
        "HTTP/1.1 %d %s\r\n"
        "Server: CS 105 Web server %s\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html>\r\n"
        "<head><title>%d %s</title></head>\r\n"
        "<center><h1>%d %s</h1></center>\r\n"
        "</body></html>\r\n",
      error_id, message,
      team,
      error_id, message,
      error_id, message);

    /*
     * Send the error to the client.  If something goes wrong in the
     * write, we don't care (since the client will fail anyway) so we can ignore
     * the error code from write.  However, some versions of gcc
     * insist that we check the error code, so we'll write a dummy if
     * statement just to get it to shut up.
     *
     * Note that if you're using this statement as a prototype for
     * code elsewhere, you SHOULD do something intelligent in the
     * error case; you SHOULD NOT just ignore it as is being done
     * here.  This is a special case where "do something intelligent"
     * equates to "do nothing" but that's highly unusual.
     */
    if (write(args->connfd, buf, nbytes) != nbytes)
        ;
}

void copy_to_client(arglist_t *args, char* request, char* path){
    int resource;
    char buf[MAXLINE];
    char* dot;
    char* content_type;
    int nbytes;
    
    // access resource
    if ((resource = open(path, O_RDONLY)) == -1){
        http_error(args, 404);
        if (pthread_mutex_lock(&mutex)!=0){
            fprintf(stderr, "Mutex lock failed.");
        }
        write_log(args, "Cannot find resource:", path);
        if (pthread_mutex_unlock(&mutex)!=0){
            fprintf(stderr, "Mutex unlock failed.");
        }
    }

    // create header
    dot = strchr(path, '.');
    if (strncmp(dot, ".gif", 4) == 0){
        content_type = "image/gif";
    }
    else if (strncmp(dot, ".jpeg", 5) == 0){
        content_type = "image/jpeg";
    }
    else if (strncmp(dot, ".html", 5) == 0){
        content_type = "text/html";
    }
    else {
        content_type = "text/plain";
    }
    nbytes = snprintf(buf, sizeof buf,
        "HTTP/1.0 200 OK\r\n"
        "Server: CS 105 Web server %s\r\n"
        "Content-Type: %s\r\n"
        "Connection: close\r\n"
        "\r\n", team, content_type);
    
    // sends header
   if (write(args->connfd, buf, nbytes)==-1){
        fprintf(stderr, "Failed to send header");
   }

    // copies resource
    while((nbytes = read(resource, buf, sizeof buf)) > 0){
        if (write(args->connfd, buf, nbytes)==-1){
            fprintf(stderr, "failed to copy resource");
        }
    }
    close(resource);
}
