#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h>

#define SOCKS5_VER 0x05
#define METHOD_NO_AUTH 0x00
#define METHOD_USERNAME_PASSWORD 0x02
#define METHOD_NO_ACCEPTABLE 0xFF

pid_t *child_pids = NULL;
int child_count = 0;

// Global authentication info
char auth_username[256] = {0};
char auth_password[256] = {0};
int use_auth = 0;

// Test configuration structure
struct test_args {
    int client_count;
    char* dest_host;
    int dest_port;
    char* proxy_addr;
    char* proxy_port;
    char* username;
    char* password;
    int use_auth;
};

static char* validate_port(const char* s) {
    char* end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
        fprintf(stderr, "port should be in the range of 1-65535: %s\n", s);
        exit(1);
        return NULL;
    }
    return (char*)s;
}

static void parse_user_pass(char* s, struct test_args* args) {
    char* p = strchr(s, ':');
    if (p == NULL) {
        fprintf(stderr, "password not found in user:pass format\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        args->username = s;
        args->password = p;
        if (strlen(args->username) == 0 || strlen(args->password) == 0) {
            fprintf(stderr, "username and password cannot be empty\n");
            exit(1);
        }
        args->use_auth = 1;
        
        // Copy to global variables for use in child processes
        strncpy(auth_username, args->username, sizeof(auth_username) - 1);
        strncpy(auth_password, args->password, sizeof(auth_password) - 1);
        use_auth = 1;
    }
}

static void version(void) {
    fprintf(stderr, "SOCKS5 concurrency test version 1.0\n"
            "ITBA Protocolos de Comunicación 2025/1\n");
}

static void usage(const char* progname) {
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h                Prints help and exits.\n"
            "   -o <proxy_addr>   Address of the SOCKS5 proxy (default: 127.0.0.1).\n"
            "   -p <proxy_port>   Port of the SOCKS5 proxy (default: 1080).\n"
            "   -d <dest_host>    Destination host to connect to through proxy (required).\n"
            "   -P <dest_port>    Destination port to connect to (required).\n"
            "   -n <n_clients>    Number of concurrent clients to spawn (required).\n"
            "   -u <user:pass>    Username and password for SOCKS5 authentication.\n"
            "   -v                Prints version information and exits.\n"
            "\n"
            "Examples:\n"
            "   %s -d google.com -P 80 -n 10\n"
            "   %s -o 192.168.1.100 -p 8080 -u user:pass -d httpbin.org -P 80 -n 5\n"
            "\n",
            progname, progname, progname);
    exit(1);
}

void parse_args(int argc, char** argv, struct test_args* args) {
    memset(args, 0, sizeof(*args));
    
    // Set defaults
    args->proxy_addr = "127.0.0.1";
    args->proxy_port = "1080";
    args->use_auth = 0;
    args->dest_host = NULL;
    args->dest_port = 0;
    args->client_count = 0;

    int c;
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help", no_argument, 0, 'h'},
            {"origin", required_argument, 0, 'o'},
            {"port", required_argument, 0, 'p'},
            {"destination", required_argument, 0, 'd'},
            {"dest-port", required_argument, 0, 'P'},
            {"clients", required_argument, 0, 'n'},
            {"user", required_argument, 0, 'u'},
            {"version", no_argument, 0, 'v'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "ho:p:d:P:n:u:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            usage(argv[0]);
            break;
        case 'o':
            args->proxy_addr = optarg;
            break;
        case 'p':
            args->proxy_port = validate_port(optarg);
            break;
        case 'd':
            args->dest_host = optarg;
            break;
        case 'P':
            args->dest_port = atoi(optarg);
            if (args->dest_port <= 0 || args->dest_port > 65535) {
                fprintf(stderr, "Invalid destination port: %d\n", args->dest_port);
                exit(1);
            }
            break;
        case 'n':
            args->client_count = atoi(optarg);
            if (args->client_count <= 0) {
                fprintf(stderr, "Number of clients must be > 0\n");
                exit(1);
            }
            break;
        case 'u':
            parse_user_pass(optarg, args);
            break;
        case 'v':
            version();
            exit(0);
        default:
            fprintf(stderr, "unknown argument %d.\n", c);
            exit(1);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Error: Unexpected positional arguments. Use options only.\n");
        usage(argv[0]);
    }

    // Check required options
    if (args->dest_host == NULL || args->dest_port == 0) {
        fprintf(stderr, "Error: Both destination host (-d) and port (-P) are required.\n");
        usage(argv[0]);
    }

    if (args->client_count == 0) {
        fprintf(stderr, "Error: Number of clients (-n) is required.\n");
        usage(argv[0]);
    }
}

void cleanup(void) {
    if (child_pids) {
        free(child_pids);
        child_pids = NULL;
    }
}

void signal_handler(int sig) {
    printf("\nSignal %d received, cleaning up...\n", sig);
    for (int i = 0; i < child_count; i++) {
        if (child_pids[i] > 0) {
            kill(child_pids[i], SIGUSR1); // Send SIGUSR1 for graceful shutdown
        }
    }
    // Wait for all children to exit
    int status;
    pid_t pid;
    for (int i = 0; i < child_count; i++) {
        if (child_pids[i] > 0) {
            pid = waitpid(child_pids[i], &status, 0);
            if (pid > 0) {
                if (WIFEXITED(status)) {
                    int code = WEXITSTATUS(status);
                    if (code != 0) {
                        fprintf(stderr, "Child %d exited with error %d\n", pid, code);
                    }
                } else if (WIFSIGNALED(status)) {
                    fprintf(stderr, "Child %d killed by signal %d\n", pid, WTERMSIG(status));
                }
            }
        }
    }
    cleanup();
    exit(0);
}

// Child process socket descriptor (global for signal handler)
int child_sockfd = -1;

void child_sigusr1_handler(int sig) {
    if (child_sockfd != -1) {
        shutdown(child_sockfd, SHUT_WR); // Send FIN
        // Optionally, read until recv returns 0 (EOF)
        char buf[256];
        while (recv(child_sockfd, buf, sizeof(buf), 0) > 0) {}
        close(child_sockfd); // Fully close socket
        child_sockfd = -1;
    }
    _exit(0); // Exit immediately
}

void sigchld_handler(int sig) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code != 0) {
                fprintf(stderr, "Child %d exited with error %d\n", pid, code);
            }
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "Child %d killed by signal %d\n", pid, WTERMSIG(status));
        }
    }
}

int connect_tcp(const char *host, int port) {
    struct addrinfo hints = {0}, *res = NULL;
    char port_str[6];
    int sockfd;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        perror("getaddrinfo");
        return -1;
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        perror("socket");
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(sockfd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return sockfd;
}

int sendall(int sockfd, const void *buf, size_t len) {
    size_t total = 0;
    const char *p = buf;
    while (total < len) {
        ssize_t sent = send(sockfd, p + total, len - total, 0);
        if (sent <= 0) return -1;
        total += sent;
    }
    return 0;
}

int recvn(int sockfd, void *buf, size_t n) {
    size_t total = 0;
    char *p = buf;
    if (buf == NULL) {
        fprintf(stderr, "Buffer pointer is NULL\n");
        return -1;
    }
    if (n <= 0) {
        fprintf(stderr, "Invalid length for recv: %zu\n", n);
        return -1;
    }
    while (total < n) {
        ssize_t rec = recv(sockfd, p + total, n - total, 0);
        if (rec <= 0) {
            fprintf(stderr, "recv failed: %s\n", strerror(errno));
            return -1;
        }
        total += rec;
    }
    return 0;
}

int socks5_handshake(int sockfd) {
    unsigned char req[3];
    unsigned char resp[2];
    
    req[0] = SOCKS5_VER;
    req[1] = use_auth ? 2 : 1;  // Number of methods
    req[2] = METHOD_NO_AUTH;    // Always offer no auth
    
    if (use_auth) {
        // Offer both no auth and username/password
        req[1] = 2;
        unsigned char req_with_auth[4];
        req_with_auth[0] = SOCKS5_VER;
        req_with_auth[1] = 2;  // 2 methods
        req_with_auth[2] = METHOD_NO_AUTH;
        req_with_auth[3] = METHOD_USERNAME_PASSWORD;
        
        if (sendall(sockfd, req_with_auth, sizeof(req_with_auth)) < 0) {
            perror("send handshake");
            return -1;
        }
    } else {
        if (sendall(sockfd, req, 3) < 0) {
            perror("send handshake");
            return -1;
        }
    }

    if (recvn(sockfd, resp, 2) < 0) {
        perror("recv handshake");
        return -1;
    }

    if (resp[0] != SOCKS5_VER) {
        fprintf(stderr, "SOCKS5 handshake failed: Invalid version %d\n", resp[0]);
        return -1;
    }
    
    if (resp[1] == METHOD_NO_ACCEPTABLE) {
        fprintf(stderr, "SOCKS5 handshake failed: No acceptable methods\n");
        return -1;
    }
    
    // If server selected username/password authentication
    if (resp[1] == METHOD_USERNAME_PASSWORD) {
        if (!use_auth) {
            fprintf(stderr, "Server requires authentication but none provided\n");
            return -1;
        }
        
        // Send username/password authentication
        size_t username_len = strlen(auth_username);
        size_t password_len = strlen(auth_password);
        size_t auth_req_len = 1 + 1 + username_len + 1 + password_len;
        
        unsigned char *auth_req = malloc(auth_req_len);
        if (!auth_req) {
            perror("malloc auth request");
            return -1;
        }
        
        size_t offset = 0;
        auth_req[offset++] = 0x01;  // Version of username/password authentication
        auth_req[offset++] = (unsigned char)username_len;
        memcpy(auth_req + offset, auth_username, username_len);
        offset += username_len;
        auth_req[offset++] = (unsigned char)password_len;
        memcpy(auth_req + offset, auth_password, password_len);
        
        if (sendall(sockfd, auth_req, auth_req_len) < 0) {
            perror("send auth request");
            free(auth_req);
            return -1;
        }
        free(auth_req);
        
        // Receive authentication response
        unsigned char auth_resp[2];
        if (recvn(sockfd, auth_resp, 2) < 0) {
            perror("recv auth response");
            return -1;
        }
        
        if (auth_resp[0] != 0x01) {
            fprintf(stderr, "Invalid auth response version: %d\n", auth_resp[0]);
            return -1;
        }
        
        if (auth_resp[1] != 0x00) {
            fprintf(stderr, "Authentication failed: status %d\n", auth_resp[1]);
            return -1;
        }
    } else if (resp[1] == METHOD_NO_ACCEPTABLE) {
        fprintf(stderr, "SOCKS5 handshake failed: Unknown method %d\n", resp[1]);
        return -1;
    }
    return 0;
}

int recv_socks5_connect_reply(int sockfd) {
    unsigned char hdr[4];
    if (recvn(sockfd, hdr, 4) < 0) {
        perror("recv connect reply header");
        return -1;
    }

    if (hdr[0] != SOCKS5_VER) {
        fprintf(stderr, "Invalid SOCKS version: %d\n", hdr[0]);
        return -1;
    }

    if (hdr[1] != 0x00) {
        fprintf(stderr, "SOCKS5 connect failed, code=%d\n", hdr[1]);
        return -1;
    }

    unsigned char atyp = hdr[3];
    size_t addr_len = 0;

    switch (atyp) {
        case 0x01: addr_len = 4; break;         // IPv4
        case 0x04: addr_len = 16; break;        // IPv6
        case 0x03: {
            unsigned char len;
            if (recvn(sockfd, &len, 1) < 0) {
                perror("recv domain length");
                return -1;
            }
            addr_len = len;
            break;
        }
        default:
            fprintf(stderr, "Unknown ATYP in reply: %d\n", atyp);
            return -1;
    }

    unsigned char addr[256];
    if (addr_len > sizeof(addr)) {
        fprintf(stderr, "Address too long in reply\n");
        return -1;
    }
    if (recvn(sockfd, addr, addr_len) < 0) {
        perror("recv address");
        return -1;
    }

    unsigned char port[2];
    if (recvn(sockfd, port, 2) < 0) {
        perror("recv port");
        return -1;
    }
    return 0;
}

int socks5_connect_domain(int sockfd, const char *domain, int port) {
    size_t dlen = strlen(domain);
    size_t req_len = 4 + 1 + dlen + 2;
    unsigned char *req = malloc(req_len);
    if (!req) return -1;

    req[0] = SOCKS5_VER;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x03;
    req[4] = (unsigned char)dlen;
    memcpy(req + 5, domain, dlen);
    req[5 + dlen] = (port >> 8) & 0xff;
    req[6 + dlen] = port & 0xff;

    if (sendall(sockfd, req, req_len) < 0) {
        perror("send connect domain");
        free(req);
        return -1;
    }
    free(req);

    return recv_socks5_connect_reply(sockfd);
}

int socks5_connect_ip(int sockfd, const char *ip_str, int port) {
    struct in_addr ip;
    if (inet_pton(AF_INET, ip_str, &ip) != 1) {
        fprintf(stderr, "Invalid IPv4 address\n");
        return -1;
    }

    unsigned char req[10];
    req[0] = SOCKS5_VER;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x01;
    memcpy(req + 4, &ip, 4);
    req[8] = (port >> 8) & 0xff;
    req[9] = port & 0xff;

    if (sendall(sockfd, req, sizeof(req)) < 0) {
        perror("send connect ip");
        return -1;
    }
    return recv_socks5_connect_reply(sockfd);
}

int run_client(const char *orig, int orig_port,const char *dest, int dest_port) {
    int sockfd = connect_tcp(orig, orig_port);
    child_sockfd = sockfd; // Set global for signal handler
    if (sockfd < 0) {
       fprintf(stderr, "Error connecting to SOCKS5 proxy\n");
       return -1;
    }

    if (socks5_handshake(sockfd) < 0) {
        close(sockfd);
        return -1;
    }

    int is_ip = 0;
    struct in_addr tmp;
    if (inet_pton(AF_INET, dest, &tmp) == 1){
        is_ip = 1;
    }
    if (is_ip) {
        if (socks5_connect_ip(sockfd, dest, dest_port) < 0) {
            close(sockfd);
            return -1;
        }
    } else {
        if (socks5_connect_domain(sockfd, dest, dest_port) < 0) {
            close(sockfd);
            return -1;
        }
    }
    char http_req[512];
    snprintf(http_req, sizeof(http_req),
             "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: c-socks5-client\r\n\r\n",
             dest);

    if (sendall(sockfd, http_req, strlen(http_req)) < 0) {
        perror("send http");
        close(sockfd);
        return -1;
    }

    while (1) {
        sleep(10);
    }

    close(sockfd);
    child_sockfd = -1;
    return 0;
}

int main(int argc, char *argv[]) {
    struct test_args args;
    parse_args(argc, argv, &args);

    child_count = args.client_count;
    const char *dest = args.dest_host;
    int dest_port = args.dest_port;
    const char *orig = args.proxy_addr;
    int org_port = atoi(args.proxy_port);

    // Handle URL parsing
    if (strncmp(dest, "http://", 7) == 0) {
        dest = dest + 7;
    }

    char host[256];
    strncpy(host, dest, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';

    char *slash = strchr(host, '/');
    if (slash) {
        *slash = '\0';
    }

    printf("Starting concurrency test:\n");
    printf("- %d clients connecting to %s:%d\n", child_count, host, dest_port);
    printf("- SOCKS5 proxy at %s:%d\n", orig, org_port);
    if (args.use_auth) {
        printf("- Using authentication: %s:***\n", args.username);
    } else {
        printf("- No authentication\n");
    }

    child_pids = calloc(child_count, sizeof(pid_t));
    if (!child_pids) {
        perror("calloc");
        return 1;
    }

    struct sigaction sa_term = {0};
    sa_term.sa_handler = signal_handler;
    sigemptyset(&sa_term.sa_mask); 
    sigaddset(&sa_term.sa_mask, SIGCHLD);
    sa_term.sa_flags = 0;
    sigaction(SIGINT, &sa_term, NULL);
    sigaction(SIGTERM, &sa_term, NULL);

    struct sigaction sa_chld = {0};
    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa_chld, NULL);

    for (int i = 0; i < child_count; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            signal_handler(SIGTERM);
        } else if (pid == 0) {
            signal(SIGINT, SIG_IGN);
            signal(SIGTERM, SIG_DFL);
            struct sigaction sa_usr1 = {0};
            sa_usr1.sa_handler = child_sigusr1_handler;
            sigemptyset(&sa_usr1.sa_mask);
            sa_usr1.sa_flags = 0;
            sigaction(SIGUSR1, &sa_usr1, NULL);
            child_sockfd = -1;
            int r = run_client(orig,org_port,host, dest_port);
            exit(r == 0 ? 0 : 1);
        } else {
            child_pids[i] = pid;
        }
    }

    while (1) {
        pause();
    }

    return 0;
}
