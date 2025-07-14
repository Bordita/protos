#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>
#include "../shared/includes/auth.h"
#include "args.h"

static char*
port(const char* s)
{
    char* end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX)
    {
        fprintf(stderr, "port should in in the range of 1-65536: %s\n", s);
        exit(1);
        return NULL;
    }
    return (char*)s;
}

static void
user(char* s, struct users* user)
{
    char* p = strchr(s, ':');
    if (p == NULL)
    {
        fprintf(stderr, "password not found\n");
        exit(1);
    }
    else
    {
        *p = 0;
        p++;
        user->name = s;
        user->pass = p;
        if (strlen(user->name) == 0 || strlen(user->pass) == 0)
        {
            fprintf(stderr, "username and password cannot be empty\n");
            exit(1);
        }
        add_user(user->name, user->pass);
    }
}

static void
version(void)
{
    fprintf(stderr, "socks5v version 0.0\n"
            "ITBA Protocolos de Comunicación 2025/1 -- Grupo X\n"
            "AQUI VA LA LICENCIA\n");
}

static void
usage(const char* progname)
{
    fprintf(stderr,
            "Usage: %s [OPTION]...\n"
            "\n"
            "   -h               Prints help and exits.\n"
            "   -l <SOCKS addr>  Address where the SOCKS proxy will be served.\n"
            "   -L <conf  addr>  Address where the management service will be served.\n"
            "   -p <SOCKS port>  Incoming port for SOCKS connections.\n"
            "   -P <conf port>   Incoming port for management connections.\n"
            "   -u <name>:<pass> Username and password for users allowed to use the proxy. Up to 10.\n"
            "   -v               Prints version information and exits.\n"
            "\n",
            progname);
    exit(1);
}

void parse_args(const int argc, char** argv, struct socks5args* args){
    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users

    args->socks_addr = NULL;
    args->socks_port = "1080";

    args->mng_addr = NULL;
    args->mng_port = "8080";

    args->disectors_enabled = true;

    int c;
    int nusers = 0;

    while (true)
    {
        int option_index = 0;
        static struct option long_options[] = {
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "hl:L:Np:P:u:v", long_options, &option_index);
        if (c == -1)
            break;

        switch (c)
        {
        case 'h':
            usage(argv[0]);
            break;
        case 'l':
            args->socks_addr = optarg;
            break;
        case 'L':
            args->mng_addr = optarg;
            break;
        case 'N':
            args->disectors_enabled = false;
            break;
        case 'p':
            args->socks_port = port(optarg);
            break;
        case 'P':
            args->mng_port = port(optarg);
            break;
        case 'u':
            if (nusers >= MAX_USERS)
            {
                fprintf(stderr, "maximun number of command line users reached: %d.\n", MAX_USERS);
                exit(1);
            }
            else
            {
                user(optarg, args->users + nusers);
                nusers++;
            }
            break;
        case 'v':
            version();
            exit(0);
        default:
            fprintf(stderr, "unknown argument %d.\n", c);
            exit(1);
        }
    }
    if (optind < argc)
    {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc)
        {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}
