#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../shared/includes/parser.h"
#include "./hotdogs.h"

#define MAX_ACTIONS 16
#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 42069
#define MAX_PORT 65535

#define SUCCESS_VALUE 0
#define ERROR_VALUE -1

static int return_value = SUCCESS_VALUE;

Action actions[MAX_ACTIONS];

char *ip_address = DEFAULT_IP;
int port_number = DEFAULT_PORT;

int free_ip = 0;
int actions_count = 0;
char *username = NULL;
char *password = NULL;

void add_action(Action action) {
    if (actions_count >= MAX_ACTIONS) {
        fprintf(stderr, "[Error] Max flags exceeded\n");
        exit(1);
    }
    actions[actions_count++] = action;
}

static void print_help(const char * program_name) {
    printf("Usage: %s [OPTION]...\n\n", program_name);
    printf("  -u user:pass         Authenticates with username and password (required)\n");
    printf("  -ip <address>        Provides server IP address (default: 127.0.0.1)\n");
    printf("  -port <port>         Provides server port (default: 42069)\n");
    printf("  -m                   Gets server metrics\n");
    printf("  -lu                  Lists users\n");
    printf("  -ll                  Lists logs\n");
    printf("  -b <size>            Sets buffer size\n");
    printf("  -add user:pass       Adds user (Maximum of 10 users)\n");
    printf("  -rm user             Removes user with username 'user'\n");
    printf("  -h                   Show this help message and terminates the connection.\n");
    printf("\n");
}

void _parse_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc) {
            char *token = strtok(argv[++i], ":");
            if (token) {
                username = strdup(token);
                token = strtok(NULL, ":");
                if (token)
                    password = strdup(token);
            }
        } else if (strcmp(argv[i], "-m") == 0) {
            Action a = { .type = ACTION_GET_METRICS, .execute = execute_get_metrics };
            add_action(a);
        } else if (strcmp(argv[i], "-lu") == 0) {
            Action a = { .type = ACTION_GET_USERS, .execute = execute_get_users };
            add_action(a);
        } else if (strcmp(argv[i], "-ll") == 0) {
            Action a = { .type = ACTION_GET_LOGS, .execute = execute_get_logs };
            add_action(a);
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            int val = atoi(argv[++i]);
            Action a = { .type = ACTION_PUT_BUFFER, .execute = execute_put_buffer };
            a.data.buffer.value = val;
            add_action(a);
        } else if (strcmp(argv[i], "-add") == 0 && i + 1 < argc) {
            char *arg = argv[++i];
            char *user = NULL, *pass = NULL;

            char *token = strtok(arg, ":");
            if (token) {
                user = strdup(token);
                token = strtok(NULL, ":");
                if (token)
                    pass = strdup(token);
            }

            if (user && pass) {
                Action a = {
                    .type = ACTION_ADD_USER,
                    .execute = execute_add_user,
                    .data.add_user = { user, pass }
                };
                add_action(a);
            } else {
                fprintf(stderr, "Error adding user (expected -add user:pass)\n");
                if(user){
                    free(user);
                }
                if(pass){
                    free(pass);
                }
                exit(1);
            }
        } else if (strcmp(argv[i], "-rm") == 0 && i + 1 < argc) {
            char *user = strdup(argv[++i]);
            if (user) {
                Action a = {
                    .type = ACTION_REMOVE_USER,
                    .execute = execute_remove_user,
                    .data.remove_user = { user }
                };
                add_action(a);
            } else {
                fprintf(stderr, "[Error] Removing user (expected -rm user)");
                exit(1);
            }
        } else if (strcmp(argv[i], "-ip") == 0 && i + 1 < argc) {
            ip_address = strdup(argv[++i]);
            free_ip = 1;
        } else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) {
            port_number = atoi(argv[++i]);
        } else {
            fprintf(stderr, "Unrecognized argument %s. Use -h for help.\n", argv[i]);
            exit(ERROR_VALUE);
        }
    }

    if (!username || !password) {
        fprintf(stderr, "[Error] Credentials not provided (-u user:pass). Use -h for help.\n");
        exit(1);
    }
}

void freeActions(Action * actions){
    for(int i=0; i < actions_count; i++){
        if(actions[i].type == ACTION_ADD_USER){
            free(actions[i].data.add_user.user);
            free(actions[i].data.add_user.pass);
        } else if(actions[i].type == ACTION_REMOVE_USER){
            free(actions[i].data.remove_user.user);
        }
    }
}

static void execute_actions(void){
    response_status execution_status = SUCCESS_RESPONSE;
    for(int i = 0; i < actions_count; i++){
        execution_status = actions[i].execute(&actions[i]);
        if(execution_status != SUCCESS_RESPONSE){
            print_error_msg(execution_status);
            return_value = ERROR_VALUE;
            return;
        }
    }
}

int main(int argc, char ** argv){
    _parse_args(argc, argv);
    if (port_number <= 0 || port_number > MAX_PORT) {
        fprintf(stderr, "[Error] Invalid port specified with -port\n");
        return_value = ERROR_VALUE;
        goto cleanup;
    }

    
    if(authenticate(username, password, ip_address, port_number) == SUCCESS_CONNECTING){
        execute_actions();
    } else {
        return_value = ERROR_VALUE;
    }

cleanup:
    freeActions(actions);
    free(username);
    free(password);
    if(free_ip){
        free(ip_address);
    }
    return return_value;
}
