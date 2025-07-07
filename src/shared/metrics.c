#include "metrics.h"

typedef struct {
    uint64_t socks5_current_connections;
    uint64_t hdp_current_connections;
    uint32_t failed_connections;
    uint64_t total_transfered_bytes;
    uint64_t historic_connections;
} Metrics;

static Metrics metrics = {
    .socks5_current_connections = 0,
    .hdp_current_connections = 0,
    .total_transfered_bytes = 0,
    .historic_connections = 0,
    .failed_connections = 0
};

void add_socks5_current_connection(void){
    metrics.socks5_current_connections++;
    metrics.historic_connections++;
}

void remove_socks5_current_connection(void){
    if (metrics.socks5_current_connections > 0)
        metrics.socks5_current_connections--;
} 

void add_hdp_current_connection(void){
    metrics.hdp_current_connections++;
    metrics.historic_connections++;
}

void remove_hdp_current_connection(void){
    if (metrics.hdp_current_connections > 0)
        metrics.hdp_current_connections--;
}

void add_transfered_bytes(int bytes){
    metrics.total_transfered_bytes += bytes;
}

void add_failed_connection(void) {
    metrics.failed_connections++;
}

int get_failed_connections(void) {
    return metrics.failed_connections;
}

int get_socks5_current_connections(void){
    return metrics.socks5_current_connections;
}

int get_hdp_current_connections(void){
    return metrics.hdp_current_connections;
}

int get_current_connections(void){
    return metrics.socks5_current_connections + metrics.hdp_current_connections;
}    

int get_transfered_bytes(void){
    return metrics.total_transfered_bytes;
}

int get_historic_connections(void){
    return metrics.historic_connections;
}    
