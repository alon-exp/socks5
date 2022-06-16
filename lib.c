#include "lib.h"
#include "log.h"

extern int server_fd;
extern ares_channel channel;
int epoll_fd;

void opt_event(int epoll_fd, int opt, struct event_data *event_data, uint32_t state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.ptr = event_data;
    if (epoll_ctl(epoll_fd, opt, event_data->fd, &ev) == -1)
    {
        LOG_DEBUG("opt_event: %s\n", strerror(errno));
    }
}

void clear_event(struct event_data *event)
{
    opt_event(epoll_fd, EPOLL_CTL_DEL, event, EPOLLIN);
    if (errno == EBADF || errno == ENOENT)
    {
        return;
    }

    if (event->to)
    {
        event->to->to = NULL;
        clear_event(event->to);
    }
    LOG_DEBUG("client close fd %d\n", event->fd);
    close(event->fd);
    free(event);
}

void epoll_start(int epoll_fd, int epoll_max_events, int timeout)
{
    struct epoll_event events[epoll_max_events];
    struct event_data *event_data;
    int fd_num;
    while (true)
    {
        fd_num = epoll_wait(epoll_fd, events, epoll_max_events, timeout);

        for (int i = 0; i < fd_num; i++)
        {
            event_data = (struct event_data *)events[i].data.ptr;

            if ((events[i].events & EPOLLHUP || events[i].events & EPOLLERR) && event_data->fd != server_fd)
            {
                // handle close / rst bit
                LOG_DEBUG("event_data epollhup close fd %d\n", event_data->fd);
                clear_event(event_data);
            }
            else if (events[i].events & EPOLLIN && event_data->type != EVENT_DATA_TYPE_DNS)
            {
                // callback function
                event_data->cb(event_data);
            }
            else if (event_data->type == EVENT_DATA_TYPE_DNS)
            {
                ares_process_fd(channel,
                                ((events[i].events) & (EPOLLIN) ? event_data->fd : ARES_SOCKET_BAD),
                                ((events[i].events) & (EPOLLOUT) ? event_data->fd : ARES_SOCKET_BAD));
            }
        }
    }
}