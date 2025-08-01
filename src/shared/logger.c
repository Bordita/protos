#include "includes/logger.h"

#define LOG_FILE "./access.log"
#define HOTDOGS_LOG_FILE "./hotdogs_access.log"
#define HOTDOGS_ACTIONS_LOG_FILE "./hotdogs_actions.log"

#define HOTDOGS_FILE_HEADER "TIMESTAMP\tUSERNAME\n"
#define HOTDOGS_FILE_LOG_FORMAT "%s\t%s\n"
#define HOTDOGS_ACTIONS_FILE_HEADER "TIMESTAMP\tUSERNAME\tACTION\tVALUES\n"
#define HOTDOGS_ACTIONS_FILE_LOG_FORMAT "%s\t%s\t%s\t%s\n"

#define TIMESTAMP_FORMAT "%Y-%m-%dT%H:%M:%SZ"
#define TIMESTAMP_SIZE 32 

#define FILE_HEADER "TIMESTAMP\tUSERNAME\tTYPE\tCLIENT_IP\tCLIENT_PORT\tDEST_ADDR\tDEST_PORT\tSTATUS\n"
#define FILE_LOG_FORMAT "%s\t%s\tA\t%s\t%u\t%s\t%u\t%u\n"

static const char *log_file = LOG_FILE;
static const char *hotdogs_log_file = HOTDOGS_LOG_FILE;
static const char *hotdogs_actions_log_file = HOTDOGS_ACTIONS_LOG_FILE;

void log_init(void) {
    FILE *file = fopen(log_file, "w");
    if (file) {
        fprintf(file, FILE_HEADER);
        fclose(file);
    }
}

void log_access(const char *username, const char *client_ip, uint16_t client_port, const char *dest_addr, uint16_t dest_port, uint8_t status_code) {
    FILE *file = fopen(log_file, "a");
    if (!file) return;

    char timestamp[TIMESTAMP_SIZE];
    time_t now = time(NULL);
    struct tm tm_info;
    gmtime_r(&now, &tm_info);
    strftime(timestamp, sizeof(timestamp), TIMESTAMP_FORMAT, &tm_info);

    fprintf(file, FILE_LOG_FORMAT, timestamp, username, client_ip, client_port, dest_addr, dest_port, status_code);
    printf(FILE_LOG_FORMAT, timestamp, username, client_ip, client_port, dest_addr, dest_port, status_code);
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

void log_hotdogs_action(const char *username, const char *action, const char *values) {
    FILE *file = fopen(hotdogs_actions_log_file, "a");
    if (!file) return;

    char timestamp[TIMESTAMP_SIZE];
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(timestamp, sizeof(timestamp), TIMESTAMP_FORMAT, &tm_info);

    fprintf(file, HOTDOGS_ACTIONS_FILE_LOG_FORMAT, timestamp, username, action, values);
    fclose(file);
}

void log_hotdogs_access(const char *username) {
    FILE *file = fopen(hotdogs_log_file, "a");
    if (!file) return;

    char timestamp[TIMESTAMP_SIZE];
    time_t now = time(NULL);
    struct tm tm_info;
    localtime_r(&now, &tm_info);
    strftime(timestamp, sizeof(timestamp), TIMESTAMP_FORMAT, &tm_info);

    fprintf(file, HOTDOGS_FILE_LOG_FORMAT, timestamp, username);
    fclose(file);
}

int get_logs_separator(char *buffer, size_t buffer_size, const char *separator, size_t size_separator){
    if (buffer == NULL || separator == NULL || buffer_size == 0) {
        return 0; 
    }
    
    buffer[0] = '\0';
    
    FILE *file = fopen(log_file, "r");
    if (!file) {
        return 0;  
    }

    char read_buffer[1024];
    size_t output_pos = 0;
    size_t bytes_read;

    while ((bytes_read = fread(read_buffer, 1, sizeof(read_buffer), file)) > 0) {
        for (size_t i = 0; i < bytes_read; i++) {
            if (read_buffer[i] == '\n') {
                if (output_pos + size_separator >= buffer_size) {
                    fclose(file);
                    buffer[output_pos] = '\0';
                    return (int)output_pos;  
                }
                memcpy(&buffer[output_pos], separator, size_separator);
                output_pos += size_separator;
            } else {
                if (output_pos >= buffer_size - 1) {
                    fclose(file);
                    buffer[output_pos] = '\0';
                    return (int)output_pos;  
                }
                buffer[output_pos] = read_buffer[i];
                output_pos++;
            }
        }
    }

    fclose(file);
    buffer[output_pos] = '\0';

    return (int)output_pos;
}
