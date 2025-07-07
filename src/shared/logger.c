#include "includes/logger.h"

#define LOG_FILE "../access.log"

#define TIMESTAMP_FORMAT "%Y-%m-%d %H:%M:%S"
#define TIMESTAMP_SIZE 20


static char *log_file = LOG_FILE;

void log_init(void) {
    FILE *file = fopen(log_file, "w");
    if (file) {
        fprintf(file, "TIMESTAMP\tUSERNAME\tCLIENT IP\tCLIENT PORT\tDEST ADDR\tDEST PORT\n");
        fclose(file);
    }
}

void log_access(const char *username, const char *client_ip, uint16_t client_port, const char *dest_addr, uint16_t dest_port){
    FILE *file = fopen(log_file, "a");
    if (!file) return;

    char timestamp[TIMESTAMP_SIZE];
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(timestamp, sizeof(timestamp), TIMESTAMP_FORMAT, &tm_info);

    fprintf(file, "%s\t%s\t%s\t%u\t%s\t%u\n", timestamp, username, client_ip, client_port, dest_addr, dest_port);
    fclose(file);
}

void clean_logs(void) {
    FILE *file = fopen(log_file, "w");
    if (file) {
        fclose(file);
    }
}

void set_log_file(const char *file_name){
    file_name ? (log_file = file_name)  : (log_file = LOG_FILE); 
}

char * get_logs(void){
    FILE *file = fopen(log_file, "r");
    if (!file) return NULL;

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = malloc(size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, size, file);
    buffer[size] = '\0';
    fclose(file);

    return buffer;
}
