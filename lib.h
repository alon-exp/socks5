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
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define EPOLL_MAX_EVENTS 64

struct event_data
{
    int fd;
    struct sockaddr_in addr;
    void (*cb)(struct event_data *event_data);
    struct event_data *to;
};

typedef void (*cb_t)(struct event_data *event_data);

void opt_event(int epollfd, int opt, struct event_data *event_data, uint32_t state);
void clear_event(struct event_data *event);
void epoll_start(int epollfd, int epoll_max_events, int timeout);

#endif