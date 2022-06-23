#include "lib.h"
#include "log.h"

static int epoll_fd;

int epoll_init(int nfds)
{
    return epoll_fd = epoll_create(nfds);
}

void add_event(struct event_data *event, uint32_t state)
{
    struct epoll_event ev;
    ev.events = state;
    ev.data.ptr = event;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event->fd, &ev) == -1)
    {
        LOG_DEBUG("epoll_ctl: %s\n", strerror(errno));
    }
}

void clear_event(struct event_data *event)
{
    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, event->fd, NULL) == -1)
    {
        LOG_DEBUG("epoll_ctl: %s\n", strerror(errno));
    }

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

void epoll_start(int listenfd, int epoll_max_events, int timeout)
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

            if ((events[i].events & EPOLLHUP || events[i].events & EPOLLERR) /* && event_data->fd != listenfd */)
            {
                // handle close / rst bit
                LOG_DEBUG("event_data epollhup close fd %d\n", event_data->fd);
                clear_event(event_data);
            }
            else if (events[i].events & EPOLLIN)
            {
                // callback function
                event_data->cb(event_data);
            }
        }
    }
}