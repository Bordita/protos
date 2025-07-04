#include <stdio.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "../shared/selector.h"
#include "serverHandle.h"
#include "../args/args.h"
#include <unistd.h>

static void sigterm_handler(const int signal) {
    char * sigtype;
    switch (signal) {
    case SIGTERM:
        sigtype = "SIGTERM";
        break;
    case SIGINT:
        sigtype = "SIGINT";
        break;
    default:
        sigtype = "UNKNOWN";
        break;
    }

    printf("\nsignal %s, cleaning up and exiting...\n", sigtype);
    server_handler_free();
  //  free_users();
    exit(0);
}





int main(int argc, char *argv[]){
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler);

    close(STDIN_FILENO);

    struct socks5args args;
    parse_args(argc, argv, &args);

    printf("\n\n---------------- START OF SOCKS5 DEBUGGING ----------------\n\n");

    printf("Arguments read:\n");
    printf("\tSocks5 Address: %s\n\tSocks5 Port: %s\n\tHot Dogs Address: %s\n\tHot Dogs Port: %s\n", args.socks_addr, args.socks_port, args.mng_addr, args.mng_port);

    int retcode = server_handler(args.socks_addr, args.socks_port, args.mng_addr, args.mng_port);

    server_handler_free();
    return retcode;
}
