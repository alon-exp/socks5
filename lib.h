#ifndef __LIB_H__
#define __LIB_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <ares.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <uthash.h>

#define EPOLL_MAX_EVENTS 64

struct event_data
{
    int fd;
    int type;
    struct sockaddr_in addr;
    void (*cb)(struct event_data *event_data);
    struct event_data *to;
};

struct dns_cache
{
    char *domain_name;
    uint32_t ipv4;
    uint8_t ipv6[16];
    UT_hash_handle hh;
};

#define EVENT_DATA_TYPE_NORMAL 1
#define EVENT_DATA_TYPE_DNS 2

typedef void (*cb_t)(struct event_data *event_data);

int epoll_init(int nfds);
void add_event(struct event_data *event, uint32_t state);
void clear_event(struct event_data *event);
void epoll_start(int listenfd, int epoll_max_events, int timeout);

#endif