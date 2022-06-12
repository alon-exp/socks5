#include "lib.h"
#include "log.h"

extern int server_fd;
int epoll_fd;

static bool isFileDescriptor(int fd)
{
    return !(-1 == fcntl(fd, F_GETFD, NULL) && errno == EBADF);
}

void opt_event(int epoll_fd, int opt, struct event_data *event_data, uint32_t state)
{
    if (!isFileDescriptor(event_data->fd))
    {
        return;
    }

    struct epoll_event ev;
    ev.events = state;
    ev.data.ptr = event_data;
    if (epoll_ctl(epoll_fd, opt, event_data->fd, &ev) == -1)
    {
        LOG_DEBUG("opt_event: %s addr: %s\n", strerror(errno), inet_ntoa(event_data->addr.sin_addr));
        // clear_event(event_data);
    }
}

void clear_event(struct event_data *event)
{
    if (!isFileDescriptor(event->fd))
    {
        return;
    }

    LOG_DEBUG("client close fd %d\n", event->fd);
    opt_event(epoll_fd, EPOLL_CTL_DEL, event, EPOLLIN);
    event->to = NULL;
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
                // handle rst bit
                if (event_data->to != NULL)
                {
                    clear_event(event_data->to);
                }
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