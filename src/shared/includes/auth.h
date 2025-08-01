#ifndef __AUTH_H__
#define __AUTH_H__

#define MAX_USERS 10

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

int add_user(const char *username, const char *password);
void remove_user(const char *username);
int authenticate_user(const char *username, const char *password);

void destroy_user_list(void);

uint16_t get_users_separator(char *buffer, size_t buffer_size, const char *separator, size_t separator_size);

bool authentication_enabled(void);

void print_user_list(void);

#endif
