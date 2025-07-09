#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void log_init(void);

void log_access(const char *username, const char *client_ip, uint16_t client_port, const char *dest_addr, uint16_t dest_port);

void clean_logs(void);

void set_log_file(const char *filename);

void log_hotdogs_access(const char *username);
void log_hotdogs_action(const char *username, const char *action, const char *values);

char * get_logs(void);
int get_logs_separator(char *buffer, size_t buffer_size, const char *separator, size_t size_separator);

#endif
