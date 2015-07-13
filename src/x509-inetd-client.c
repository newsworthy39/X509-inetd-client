// x509-inetd-client.c
// As described on http://simplestcodings.blogspot.dk/2010/08/secure-server-client-using-openssl-in-c.html
// The client, is not a provisioning mechanism, but a container-based watchdog.

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <dirent.h>
#include <fcntl.h>
#include <wait.h>

#define FAIL    -1

// Used, when controlling output from children to do IPC.
#define FORKOK 0
#define FORKOKSHARE 2
#define FORKEXITABORT 1

struct STDINSTDOUT {
    char buffer_in[4096];
    unsigned int offset_in;
    char buffer_out[4096];
    unsigned int offset_out;
};

char *hostname = "localhost", *portnum = "5001", *directory = "", *files = "",
        *crt = "mycrt.pem", *authority = NULL;

// default is to use nobody when forking.
unsigned int children = 0, maxchildren = 5, uid = 65534, gid = 65534;

/**
 * Execute a file, using fork and dup2(pipe)
 * @Param char *name[] = { prog, szbuf, NULL };
 */
int execute(char **argv) {
    pid_t pid;
    int status;
    int pipefd[2];
    pipe(pipefd);

    /* Set O_NONBLOCK flag for the read end (pfd[0]) of the pipe. */
    if (fcntl(pipefd[0], F_SETFL, O_NONBLOCK) == -1) {
        fprintf(stderr, "Call to fcntl failed.\n");
        exit(1);
    }

    if ((pid = fork()) < 0) { /* fork a child process           */
        fprintf(stderr, "Forking child process failed\n");
        exit(1);
    } else if (pid == 0) { /* for the child process:         */

        close(pipefd[0]);    // close reading end in the child

        dup2(pipefd[1], 1);  // send stdout to the pipe
        dup2(pipefd[1], 2);  // send stderr to the pipe

        close(pipefd[1]);    // this descriptor is no longer needed

        // This replaces my current image, and executes within theese privileges.
        if (execv(*argv, argv) < 0) { /* execute the command  */
            fprintf(stderr, "Executing process %s failed\n", argv[0]);
            exit(-1);
        }

        // Anythere here, will never bee seen.
    } else { /* for the parent:      */
        while (waitpid(-1, &status, 0) != pid) {
#ifdef __DEBUG__
            printf("The child-process is waiting.\n");
#endif
        }

#ifdef __DEBUG__
        printf("Child exit-status: %d, %d\n", WEXITSTATUS(status), errno);
#endif

        // parent
        char buffer[4096];
        bzero(buffer, sizeof(buffer));

        close(pipefd[1]);  // close the write end of the pipe in the parent

        int nread = 0;
        switch (nread = read(pipefd[0], buffer, sizeof(buffer))) {
        case -1: /* Make sure that pipe is empty. */
            if (errno == EAGAIN) {
                printf("Parent: Pipe is empty\n");
                fflush(stdout);
                sleep(1);
            } else { /* Reading from pipe failed. */
                fprintf(stderr, "Parent: Couldn’t read from pipe.\n");
                fflush(stdout);
            }
            break;
        case 0: /* Pipe has been closed. */
//          printf("Parent: End of conversation.\n"); break;
        default: /* Received a message from the pipe. */
            strncpy(&(argv[2])[0], buffer, nread); // Remove that annoying trailing newline + fflush.
            break;
        } /* End of switch. */

        return WEXITSTATUS(status);
    }

    return 0; // is ok.
}

/**
 * Check for the existance of a file.
 */
int fileExists(const char *fname) {
    FILE *file;
    if ((file = fopen(fname, "r"))) {
        fclose(file);
        return 1;
    }
    return 0;
}

/**
 * ExecuteDirectory.
 * Executes the content of a directory (not-recursive). When it encountes an exec, that returns exit(1), then
 * it halts processing, because it signals the claim of responsibility. This can be used, to implement chain-of-responsibilites.
 * @param fqdn The file, to run ( files should be marked with +x).
 * @param struct STDINSTDOUT * stdinout The input buffer, as received from the client.
 * @return int if not.
 */
int executeFile(const char * filename, struct STDINSTDOUT * stdinout) {

    char * pcf = strtok(filename, ":");

    while (pcf != NULL) {

#ifdef __DEBUG__
        printf("SERVER EXECUTING FILE: %s\n", pcf);
#endif

        char szbuf[4096];
        bzero(szbuf, sizeof(szbuf));

        const char *name[] = { pcf, &stdinout->buffer_in[0], szbuf,
        NULL };

        int exit_signal = execute(name);
        switch (exit_signal) {

        // all is well, but output are to be put in inputbuffer.
        case FORKOKSHARE: {

            if (strlen(szbuf) > 0) {
                // lets copy it into the input-buffer, allowing us to 'share' it
                // with the others.
                stdinout->offset_in += sprintf(
                        &stdinout->buffer_in[stdinout->offset_in], "%s", szbuf);
            }

        }
            break;

            // All is not well. Abort execution, output into outputbuffer and send to client
        case FORKEXITABORT: {
            if (strlen(szbuf) > 0) {
                stdinout->offset_out += sprintf(
                        &stdinout->buffer_out[stdinout->offset_out], "%s",
                        szbuf);
            }

            return FORKEXITABORT;

        }
            break;

            // All is well, copy output to outputbuffer.
        default: {
            if (strlen(szbuf) > 0) {
                stdinout->offset_out += sprintf(
                        &stdinout->buffer_out[stdinout->offset_out], "%s",
                        szbuf);

            }

        }

            break;
        }

        pcf = strtok(NULL, ":");
    }

    return 0;

}

/**
 * ExecuteDirectory.
 * Executes the content of a directory (not-recursive). When it encountes an exec, that returns exit(1), then
 * it halts processing, because it signals the claim of responsibility. This can be used, to implement chain-of-responsibilites.
 * @param dir_name The directory, into which, recursively to look for files, to execute (files, containing with +x).
 * @param struct STDINSTDOUT * stdinout The input/output struct,
 * @return none.
 */
void executeDirectory(const char * dir_name, struct STDINSTDOUT * stdinout) {

    DIR * d;

    /* Open the directory specified by "dir_name". */

    d = opendir(dir_name);

    /* Check it was opened. */
    if (!d) {
        fprintf(stderr, "Cannot open directory '%s': %s\n", dir_name,
                strerror(errno));
        return;
    }

    while (1) {
        struct dirent * entry;
        const char * d_name;

        /* "Readdir" gets subsequent entries from "d". */
        entry = readdir(d);
        if (!entry) {
            /* There are no more entries in this directory, so break
             out of the while loop. */
            break;
        }
        d_name = entry->d_name;

        /* If you don't want to print the directories, use the
         following line:, and also - skip the files with a . */

        if (!(entry->d_type & DT_DIR)) {
            if (strncmp(d_name, ".", 1) != 0) {

                char filename[255];
                bzero(filename, sizeof(filename));
                sprintf(filename, "%s/%s", dir_name, d_name);

                int abort = executeFile(filename, stdinout);

                if (abort == FORKEXITABORT) {
#ifdef __DEBUG__
                    printf("Child exited with abort-code.\n");
#endif
                    break;
                }

            }
        }
    }

//#endif /* 0 */

//      if (entry->d_type & DT_DIR) {
//
//          /* Check that the directory is not "d" or d's parent. */
//
//          if (strcmp(d_name, "..") != 0 && strcmp(d_name, ".") != 0) {
//              int path_length;
//              char path[PATH_MAX];
//
//              path_length = snprintf(path, PATH_MAX, "%s/%s", dir_name,
//                      d_name);
//              printf("%s\n", path);
//              if (path_length >= PATH_MAX) {
//                  fprintf(stderr, "Path length has got too long.\n");
//                  exit(EXIT_FAILURE);
//              }
//
//              /* Recursively call "list_dir" with the new path. */
//              ExecuteDirectory(path, buffer_in, buffer_out, offset);
//          }
//      }

    /* After going through all the entries, close the directory. */
    if (closedir(d)) {
        fprintf(stderr, "Could not close '%s': %s\n", dir_name,
                strerror(errno));
        exit(EXIT_FAILURE);

    }
}

/**
 * OpenConnection
 * @param hostname the hostname, to connect to
 * @param port the port to connect to.
 */
int openConnection(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*) (host->h_addr);
    if (connect(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0) {
        close(sd);
        return -1;
    }
    return sd;
}

SSL_CTX* initCTX(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms(); /* Load cryptos, et.al. */
    SSL_load_error_strings(); /* Bring in and register error messages */
    method = TLSv1_2_client_method(); /* Create new client-method instance */
    ctx = SSL_CTX_new(method); /* Create new context */
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

/**
 * ShowCerts
 * Show the certificate information, but only if debug.
 * @param SSL*
 * @return void
 */
void showCertificates(SSL* ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL) {
#ifdef __DEBUG__
        printf("x509-inetd-client received certificates:\n");
#endif
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
#ifdef __DEBUG__
        printf("Subject: %s\n", line);
#endif
        free(line); /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
#ifdef __DEBUG__
        printf("Issuer: %s\n", line);
#endif
        free(line); /* free the malloc'ed string */
        X509_free(cert); /* free the malloc'ed certificate copy */
    } else
        printf("No certificates.\n");
}

int loadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    /* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {

    int server, c, index, norunscripts = 1;
    char *hostname = "localhost", *portnum = "5001", *directory =
            "/etc/etherclient.d", *crt = "mycrt.pem";

    struct STDINSTDOUT tt = { .buffer_in = { 0 }, .buffer_out = { 0 },
            .offset_in = 0, .offset_out = 0 };

    while ((c = getopt(argc, argv, "h:p:d:c:n")) != -1)
        switch (c) {
        case 'h':
            hostname = optarg;
            break;
        case 'p':
            portnum = optarg;
            break;
        case 'd':
            directory = optarg;
            break;
        case 'c':
            crt = optarg;
            break;
        case 'n':
            norunscripts = 0;
            break;
        case '?':
            if (optopt == 'c')
                fprintf(stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
            return 1;
        default:
            printf(
                    "\n-h(ost) = %s, -p(ort) = %s,"
                            "\n-f(ile, multiple paths seperated with a ':') = % s,"
                            "\n-d(irectory, multiple directories seperated with a ':') = %s,"
                            "\n-c(ertificate-bundle) = %s,"
                            "\n-m(ax children) = %d\n"
                            "\n-u(ser id) = %d\n"
                            "\n-g(group ud) = %d\n", hostname, portnum, files,
                    directory, crt, maxchildren, uid, gid);
            abort();
        }

    for (index = optind; index < argc; index++) {
        printf("Non-option argument %s\n", argv[index]);
        return 0;
    }

    // SSL Stuff.
    SSL_CTX *ctx;
    SSL *ssl;

    SSL_library_init();

    ctx = initCTX();

    // Load certificates, but make sure to bail with an error, to play nice with pipes etc.
    if (-1 == loadCertificates(ctx, crt, crt)) {
        printf("error: Could not load certificates, %s, key: %s\n", crt, crt);
        exit(EXIT_FAILURE);
    }

    int abort = FORKOK;
    if (strlen(files) > 0 && norunscripts == 1) {
        if (FORKEXITABORT == executeFile(files, &tt)) {
            exit(0);
        }
    }

    char * pcf = strtok(hostname, ":");

    // double-while for shitty connect-disconnect semantics..
    while (pcf != NULL) {
        while (pcf != NULL) {

            // Connect to the endpoint.
            if (-1 != (server = openConnection(pcf, atoi(portnum)))) {
                printf("error: Could not connect, to %s:%d\n", pcf,
                        atoi(portnum));

                // advance
                pcf = strtok(NULL, ":");

                break;
            }

            ssl = SSL_new(ctx); /* create new SSL connection state */
            SSL_set_fd(ssl, server); /* attach the socket descriptor */

            if (SSL_connect(ssl) == FAIL) { /* perform the connection */
                ERR_print_errors_fp(stderr);

                // advance our list.
                pcf = strtok(NULL, ":");
                break;
            } else {

#ifdef ___DEBUG__
                printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
#endif
                showCertificates(ssl); /* get any certs */

                /* If we explicitly disallowed scripts, skip this */
                if (norunscripts == 1 && abort != FORKEXITABORT) {
                    executeDirectory(directory, &tt);
                }

                /** If our buffer is empty, we'll send a zero-packet, to identify ourselves at the receiver-end */
                if (tt.offset_out < 1) {
                    tt.buffer_out[0] = 10;
                    tt.offset_out = 1;
                }

                SSL_write(ssl, &(tt.buffer_out[0]), tt.offset_out); /* encrypt & send message */

                /* An OK sent, is received by a simple 1. */
                tt.offset_in = SSL_read(ssl, tt.buffer_in,
                        sizeof(tt.buffer_in)); /* get reply & decrypt */

                if (tt.offset_in < 1) {
                    printf(
                            "Error: Did not received OK statement. Payload not delivered, bytes: %d.\n",
                            tt.offset_in);
                } else {
                    // If there is input.
#ifdef __DEBUG__
                    printf("X509-inetd-client received:\n%s", tt.buffer_in);
#else
                    printf("%s", tt.buffer_in);
#endif
                }

                /* Free the result */
                SSL_free(ssl); /* release connection state */

            }

            close(server); /* close socket */

            // Advance to next host.
            pcf = strtok(NULL, ":");
        } // end while, strtok
    } // end retry-list-loop.

    SSL_CTX_free(ctx); /* release context */

    // Make sure, we play nice with other programs.
    if (tt.offset_in > 1)
        exit(EXIT_SUCCESS);
    else
        exit(EXIT_FAILURE);
}
