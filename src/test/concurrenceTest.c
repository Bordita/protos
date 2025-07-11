#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>

#define SOCKS5_VER 0x05

pid_t *child_pids = NULL;
int child_count = 0;


void cleanup() {
    if (child_pids) {
        free(child_pids);
        child_pids = NULL;
    }
}

void signal_handler(int sig) {
    printf("\nSignal %d received, cleaning up...\n", sig);
    for (int i = 0; i < child_count; i++) {
        if (child_pids[i] > 0) {
            kill(child_pids[i], SIGTERM);
        }
    }
    cleanup();
    exit(0);
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
    unsigned char req[] = {SOCKS5_VER, 1, 0x00};
    unsigned char resp[2];

    if (sendall(sockfd, req, sizeof(req)) < 0) {
        perror("send handshake");
        return -1;
    }

    if (recvn(sockfd, resp, 2) < 0) {
        perror("recv handshake");
        return -1;
    }

    if (resp[0] != SOCKS5_VER || resp[1] != 0x00) {
        fprintf(stderr, "SOCKS5 handshake failed: VER=%d METHOD=%d\n", resp[0], resp[1]);
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
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <n_clients> <destination_host> <destination_port> [<proxy_ip> <proxy_port>] \n", argv[0]);
        return 1;
    }

    child_count = atoi(argv[1]);
    if (child_count <= 0) {
        fprintf(stderr, "Number of clients must be > 0\n");
        return 1;
    }
    const char *url = argv[2];
    const char *dest = url;
    int dest_port = atoi(argv[3]);
    const char *orig;    
    int org_port;

    if (strncmp(url, "http://", 7) == 0) {
        dest = url + 7;
    }

    if (strncmp(url, "http://", 7) == 0) {
    dest = url + 7;
}

    char host[256];
    strncpy(host, dest, sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';

    char *slash = strchr(host, '/');
    if (slash) {
        *slash = '\0';
    }

    if(argc > 5){
        orig = argv[4];
        org_port = atoi(argv[5]);
    }
    else{
        orig = "127.0.0.1";
        org_port = 1080;
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
