#ifndef __AUTH_H__
#define __AUTH_H__

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

int add_user(const char *username, const char *password);
void remove_user(const char *username);
int authenticate_user(const char *username, const char *password);

void destroy_user_list(void);

bool authentication_enabled(void);

#endif
