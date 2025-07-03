#ifndef __METRICS_H__
#define __METRICS_H__

#include <stdint.h>

// TODO: check if can use <stdatomic.h> for atomic operations

void add_socks5_current_connection(void);
void remove_sockks5_current_connection(void);
int get_socks5_current_connections(void);

void add_hdp_current_connection(void);
void remove_hdp_current_connection(void);
int get_hdp_current_connections(void);

void add_transfered_bytes(int bytes); // Add bytes to the total transfer bytes

int get_current_connections(void);    // Get the number of current connections
int get_transfered_bytes(void);            // Get the total transfer bytes
int get_historic_connections(void);    // Get the total number of connections

#endif
