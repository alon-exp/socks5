#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <signal.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "log.h"
#include "util.h"
#include "lib.h"
#include "proto.h"
#include "server.h"

#define BUF_SIZE 4096
#define LISTEN_PORT 1080
#define MAX_WORKERS 4

extern int epoll_fd;
int server_fd;

static void method_reply_cb(struct event_data *client_event)
{
    int recvlen, sendlen;
    uint8_t rx[MAX_METHOD_REQUEST_LEN] = {0}, tx[MAX_METHOD_REPLY_LEN] = {0};
    struct method_request *method_request = (struct method_request *)rx;
    struct method_reply *method_replay = (struct method_reply *)tx;

    recvlen = recv(client_event->fd, rx, MAX_METHOD_REQUEST_LEN, 0);
    if (recvlen == -1)
    {
        LOG_DEBUG("%s\n", strerror(errno));
        if (errno == EAGAIN)
        {
            return;
        }
    }

    // check the validity of the packet
    if (check_validity(rx, recvlen, SOCKS5_METHOD_REQUEST))
    {
        method_replay->ver = VERSION;
        if (check_method(rx, USERNAME_PASSWORD))
        {
            method_replay->method = USERNAME_PASSWORD;
            sendlen = send(client_event->fd, tx, MAX_METHOD_REPLY_LEN, 0);
            if (sendlen == -1)
            {
                LOG_DEBUG("%s\n", strerror(errno));
                clear_event(client_event);
                return;
            }
            // move to the next step
            client_event->cb = auth_cb;
        }
        else if (check_method(rx, NO_AUTHENTICATION_REQUIRED))
        {
            method_replay->method = NO_AUTHENTICATION_REQUIRED;
            sendlen = send(client_event->fd, tx, MAX_METHOD_REPLY_LEN, 0);
            if (sendlen == -1)
            {
                LOG_DEBUG("%s\n", strerror(errno));
                // close(client_event->fd);
                clear_event(client_event);
                return;
            }
            // move to the next step
            client_event->cb = socks_reply_cb;
        }
        else
        {
            method_replay->method = NO_ACCEPTABLE_METHODS;
            sendlen = send(client_event->fd, tx, MAX_METHOD_REPLY_LEN, 0);
            if (sendlen == -1)
            {
                LOG_DEBUG("%s\n", strerror(errno));
            }
            clear_event(client_event);
        }
    }
    else
    {
        clear_event(client_event);
    }
}

static void conn_relay(struct event_data *client_event, struct socks_request *socks_request)
{
    int sendlen;
    uint8_t tx[MAX_SOCKS_REPLY_LEN] = {0};
    struct socks_reply *socks_reply = (struct socks_reply *)tx;

    // ipv4 or domain
    if (socks_request->atyp == IPV4 || socks_request->atyp == DOMAIN)
    {
        int remote_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct event_data *remote_event = (struct event_data *)malloc(sizeof(struct event_data));
        struct sockaddr_in remote_addr;
        memset(&remote_addr, '\0', sizeof(remote_addr));

        in_addr_t dst_addr;
        in_port_t dst_port;
        if (socks_request->atyp == DOMAIN)
        {
            int atyp;
            char *domain = (char *)malloc(socks_request->dst.domain.len + 1);
            // memset(domain, '\0', socks_request->dst.domain.len + 1);
            domain[socks_request->dst.domain.len] = '\0';
            memcpy(domain, socks_request->dst.domain.str, socks_request->dst.domain.len);
            dst_addr = resolve_domain(domain, &atyp);
            if (dst_addr == 0U)
            {
                LOG_DEBUG("resolve error: %s\n", domain);
            }
            else
            {
                LOG_DEBUG("resolve success: %s\n", domain);
            }
            memcpy(&dst_port, socks_request->dst.domain.str + socks_request->dst.domain.len, 2);
            free(domain);
        }
        else
        {
            dst_addr = socks_request->dst.ipv4.addr;
            dst_port = socks_request->dst.ipv4.port;
        }

        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = dst_port;
        remote_addr.sin_addr.s_addr = dst_addr;

        LOG_DEBUG("remote_ip: %s\n", inet_ntoa(remote_addr.sin_addr));

        in_addr_t local_addr;
        in_port_t local_port;
        get_local_sockaddr(remote_fd, &local_addr, &local_port);

        socks_reply->ver = VERSION;
        socks_reply->rsv = RESERVED;
        socks_reply->atyp = IPV4;
        socks_reply->bnd.ipv4.addr = local_addr;
        socks_reply->bnd.ipv4.port = local_port;

        if (connect(remote_fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr)) == -1)
        {
            LOG_DEBUG("%s\n", strerror(errno));

            switch (errno)
            {
            case ENETUNREACH:
                socks_reply->rep = NETWORK_UNREACHABLE;
                break;
            case EHOSTUNREACH:
                socks_reply->rep = HOST_UNREACHABLE;
                break;
            case ETIMEDOUT:
                socks_reply->rep = TTL_EXPIRED;
                break;
            case ECONNREFUSED:
                socks_reply->rep = CONNECTION_REFUSED;
                break;
            default:
                socks_reply->rep = GENERAL_SOCKS_SERVER_FAILURE;
                break;
            }

            // if (dst_addr == inet_addr("127.0.0.1"))
            // {
            //     socks_reply->rep = CONNECTION_NOT_ALLOWED_BY_RULESET;
            // }

            sendlen = send(client_event->fd, tx, MIN_SOCKS_REPLY_LEN, 0);
            if (sendlen == -1)
            {
                LOG_DEBUG("%s\n", strerror(errno));
            }

            clear_event(client_event);
            close(remote_fd);
            free(remote_event);
            // clear_event(remote_event);
        }
        else
        {
            socks_reply->rep = SUCCEEDED;

            sendlen = send(client_event->fd, tx, MIN_SOCKS_REPLY_LEN, 0);
            if (sendlen == -1)
            {
                LOG_DEBUG("%s\n", strerror(errno));
                clear_event(client_event);
                close(remote_fd);
                free(remote_event);
                return;
            }

            // remote_event
            remote_event->addr = remote_addr;
            remote_event->fd = remote_fd;
            remote_event->cb = tcp_relay_cb;
            remote_event->to = client_event;

            // client_event
            client_event->to = remote_event;
            client_event->cb = tcp_relay_cb;
            opt_event(epoll_fd, EPOLL_CTL_ADD, remote_event, EPOLLIN);
        }
    }
    else
    {
        not_support(client_event, socks_request, ADDRESS_TYPE_NOT_SUPPORTED);
    }
}

static void bind_relay(struct event_data *client_event, struct socks_request *socks_request)
{
    not_support(client_event, socks_request, COMMAND_NOT_SUPPORTED);
}

static void udp_relay(struct event_data *client_event, struct socks_request *socks_request)
{
    int sendlen;
    uint8_t tx[MAX_SOCKS_REPLY_LEN] = {0};
    struct socks_reply *socks_reply = (struct socks_reply *)tx;

    // ipv4 or domain
    if (socks_request->atyp == IPV4 || socks_request->atyp == DOMAIN)
    {
        struct sockaddr_in server_addr, client_addr;
        struct event_data *client_udp_event = (struct event_data *)malloc(sizeof(struct event_data));

        in_addr_t src_addr;
        in_port_t src_port;
        if (socks_request->atyp == DOMAIN)
        {
            int atyp;
            char *domain = (char *)malloc(socks_request->dst.domain.len + 1);
            // memset(domain, '\0', socks_request->dst.domain.len + 1);
            domain[socks_request->dst.domain.len] = '\0';
            memcpy(domain, socks_request->dst.domain.str, socks_request->dst.domain.len);
            src_addr = resolve_domain(domain, &atyp);
            if (src_addr == 0U)
            {
                LOG_DEBUG("resolve error: %s\n", domain);
            }
            else
            {
                LOG_DEBUG("resolve success: %s\n", domain);
            }
            memcpy(&src_port, socks_request->dst.domain.str + socks_request->dst.domain.len, 2);
            free(domain);
        }
        else
        {
            src_addr = socks_request->dst.ipv4.addr;
            src_port = socks_request->dst.ipv4.port;
        }

        client_addr.sin_family = AF_INET;
        client_addr.sin_addr.s_addr = src_addr;
        client_addr.sin_port = src_port;

        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        int udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int ret = bind(udp_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));

        in_addr_t bnd_addr;
        in_port_t bnd_port;
        get_local_sockaddr(udp_fd, &bnd_addr, &bnd_port);

        socks_reply->ver = VERSION;
        socks_reply->rep = SUCCEEDED;
        socks_reply->rsv = RESERVED;
        socks_reply->atyp = IPV4;
        socks_reply->bnd.ipv4.addr = bnd_addr;
        socks_reply->bnd.ipv4.port = bnd_port;

        if (ret == -1)
        {
            LOG_DEBUG("%s\n", strerror(errno));
            socks_reply->rep = GENERAL_SOCKS_SERVER_FAILURE;
            sendlen = send(client_event->fd, tx, MIN_SOCKS_REPLY_LEN, 0);
            if (sendlen == -1)
            {
                LOG_DEBUG("%s\n", strerror(errno));
            }
            clear_event(client_event);
            close(udp_fd);
            free(client_udp_event);
        }
        else
        {
            sendlen = send(client_event->fd, tx, MIN_SOCKS_REPLY_LEN, 0);
            if (sendlen == -1)
            {
                LOG_DEBUG("%s\n", strerror(errno));
                clear_event(client_event);
                close(udp_fd);
                free(client_udp_event);
                return;
            }

            client_udp_event->addr = client_addr;
            client_udp_event->fd = udp_fd;
            client_udp_event->cb = udp_relay_cb;
            client_udp_event->to = NULL;
            opt_event(epoll_fd, EPOLL_CTL_ADD, client_udp_event, EPOLLIN);
        }
    }
    else
    {
        not_support(client_event, socks_request, ADDRESS_TYPE_NOT_SUPPORTED);
    }
}

static void not_support(struct event_data *client_event, struct socks_request *socks_request, uint8_t rep)
{
    int sendlen;
    uint8_t tx[MAX_SOCKS_REPLY_LEN] = {0};
    struct socks_reply *socks_reply = (struct socks_reply *)tx;

    socks_reply->ver = VERSION;
    socks_reply->rep = rep;
    socks_reply->rsv = RESERVED;
    socks_reply->atyp = IPV4;
    socks_reply->bnd.ipv4.addr = htonl(INADDR_ANY);
    socks_reply->bnd.ipv4.port = htons(0);
    sendlen = send(client_event->fd, tx, MIN_SOCKS_REPLY_LEN, 0);
    if (sendlen == -1)
    {
        LOG_DEBUG("%s\n", strerror(errno));
    }
    clear_event(client_event);
}

static void socks_reply_cb(struct event_data *client_event)
{
    int recvlen, sendlen;
    uint8_t rx[MAX_SOCKS_REQUEST_LEN] = {0};
    struct socks_request *socks_request = (struct socks_request *)rx;

    recvlen = recv(client_event->fd, rx, MAX_SOCKS_REQUEST_LEN, 0);
    if (recvlen == -1)
    {
        perror("tcp_relay_cb_recv");
        if (errno == EAGAIN)
        {
            return;
        }
    }

    // check the validity of the packet
    if (!check_validity(rx, recvlen, SOCKS5_SOCKS_REQUEST))
    {
        clear_event(client_event);
        return;
    }

    switch (socks_request->cmd)
    {
    case CONNECT:
        conn_relay(client_event, socks_request);
        break;
    case BIND:
        // bind_relay(client_event, socks_request);
        not_support(client_event, socks_request, COMMAND_NOT_SUPPORTED);
        break;
    case UDP_ASSOCIATE:
        udp_relay(client_event, socks_request);
        // not_support(client_event, socks_request, COMMAND_NOT_SUPPORTED);
        break;
    default:
        not_support(client_event, socks_request, COMMAND_NOT_SUPPORTED);
        break;
    }
}

static void tcp_relay_cb(struct event_data *event)
{
    int recvlen, sendlen;
    uint8_t buf[BUF_SIZE] = {0};

    recvlen = recv(event->fd, buf, BUF_SIZE, 0);
    if (recvlen > 0)
    {
        sendlen = send(event->to->fd, buf, recvlen, 0);
        if (sendlen == -1)
        {
            LOG_DEBUG("%s\n", strerror(errno));
        }
    }
    else if (recvlen == 0)
    {
        shutdown(event->fd, SHUT_RD);
        shutdown(event->to->fd, SHUT_WR);
    }
}

static void udp_relay_cb(struct event_data *event)
{
    int recvlen, sendlen;
    uint8_t rx[BUF_SIZE] = {0}, tx[BUF_SIZE] = {0};
    struct socks_udp_header *udp_request = (struct socks_udp_header *)rx;
    struct socks_udp_header *udp_reply = (struct socks_udp_header *)tx;
    struct sockaddr_in sender_udp_addr;

    socklen_t sender_udp_addr_len = sizeof(struct sockaddr_in);
    recvlen = recvfrom(event->fd, rx, BUF_SIZE, 0, (struct sockaddr *)&sender_udp_addr, &sender_udp_addr_len);
    if (recvlen == -1)
    {
        if (errno == EAGAIN)
        {
            return;
        }
        LOG_DEBUG("%s\n", strerror(errno));
    }

    // check the validity of the packet

    if (sender_udp_addr.sin_addr.s_addr == event->addr.sin_addr.s_addr && sender_udp_addr.sin_port == event->addr.sin_port)
    {
        if (udp_request->atyp == IPV4 || udp_request->atyp == DOMAIN)
        {

            int remote_udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            struct event_data *remote_udp_event = (struct event_data *)malloc(sizeof(struct event_data));
            struct event_data *client_udp_event = event;
            struct sockaddr_in remote_udp_addr;

            in_addr_t dst_addr;
            in_port_t dst_port;
            if (udp_request->atyp == DOMAIN)
            {
                int atyp;
                char *domain = (char *)malloc(udp_request->dst.domain.len + 1);
                // memset(domain, '\0', socks_request->dst.domain.len + 1);
                domain[udp_request->dst.domain.len] = '\0';
                memcpy(domain, udp_request->dst.domain.str, udp_request->dst.domain.len);
                dst_addr = resolve_domain(domain, &atyp);
                if (dst_addr == 0U)
                {
                    LOG_DEBUG("resolve error: %s\n", domain);
                }
                else
                {
                    LOG_DEBUG("resolve success: %s\n", domain);
                }
                memcpy(&dst_port, udp_request->dst.domain.str + udp_request->dst.domain.len, 2);
                free(domain);
            }
            else
            {
                dst_addr = udp_request->dst.ipv4.addr;
                dst_port = udp_request->dst.ipv4.port;
            }

            remote_udp_addr.sin_family = AF_INET;
            remote_udp_addr.sin_addr.s_addr = dst_addr;
            remote_udp_addr.sin_port = dst_port;

            int del_len;
            char *payload = del_socks_udp_header(udp_request, NULL, &del_len);
            sendlen = sendto(remote_udp_fd, payload, recvlen - del_len, 0, (struct sockaddr *)&remote_udp_addr, sizeof(remote_udp_addr));
            if (sendlen == -1)
            {
                close(remote_udp_fd);
                free(remote_udp_event);
                return;
            }

            memset(&remote_udp_event->addr, 0, sizeof(struct sockaddr));
            remote_udp_event->fd = remote_udp_fd;
            remote_udp_event->cb = udp_relay_cb;
            remote_udp_event->to = client_udp_event;

            client_udp_event->to = remote_udp_event;
            client_udp_event->cb = udp_relay_cb;
            opt_event(epoll_fd, EPOLL_CTL_ADD, remote_udp_event, EPOLLIN);
        }
    }
    else
    {
        int add_len;
        in_addr_t remote_udp_addr;
        in_port_t remote_udp_port;
        get_peer_sockaddr(event->fd, &remote_udp_addr, &remote_udp_port);
        add_socks_udp_header(udp_reply, rx, remote_udp_addr, remote_udp_port, &add_len);
        sendlen = sendto(event->to->fd, udp_relay, recvlen + add_len, 0, (struct sockaddr *)&event->to->addr, sizeof(struct sockaddr));
        if (sendlen == -1)
        {
            return;
        }
    }
}

static void auth_cb(struct event_data *client_event)
{
    int recvlen, sendlen;
    uint8_t rx[MAX_AUTH_REQUEST_LEN] = {0}, tx[AUTH_REPLY_LEN] = {0};
    struct auth_request_ver *auth_request_ver = (struct auth_request_ver *)rx;
    struct auth_reply *auth_reply = (struct auth_reply *)tx;

    recvlen = recv(client_event->fd, rx, MAX_AUTH_REQUEST_LEN, 0);
    if (recvlen == -1)
    {
        perror("auth_cb_recv");
        if (errno == EAGAIN)
        {
            return;
        }
    }

    // after recv
    struct auth_request_uname *auth_request_uname = (struct auth_request_uname *)rx + 1;
    struct auth_request_passwd *auth_request_passwd = (struct auth_request_passwd *)rx + 2 + auth_request_uname->ulen;
    char *uname = (char *)malloc(auth_request_uname->ulen + 1);
    char *passwd = (char *)malloc(auth_request_passwd->plen + 1);
    memcpy(uname, auth_request_uname->uname, auth_request_uname->ulen);
    memcpy(passwd, auth_request_passwd->passwd, auth_request_passwd->plen);
    uname[auth_request_uname->ulen] = '\0';
    passwd[auth_request_passwd->plen] = '\0';

    auth_reply->ver = AUTH_VERSION;
    if (!strcmp(uname, "dev") && !strcmp(passwd, "123456"))
    {
        LOG_DEBUG("auth_success\n");
        auth_reply->status = AUTH_SUCCESS;
        sendlen = send(client_event->fd, tx, AUTH_REPLY_LEN, 0);
        if (sendlen == -1)
        {
            LOG_DEBUG("%s\n", strerror(errno));
            clear_event(client_event);
            free(uname);
            free(passwd);
            return;
        }
        client_event->cb = socks_reply_cb;
    }
    else
    {
        LOG_DEBUG("auth_failure\n");
        auth_reply->status = AUTH_FAILURE;
        sendlen = send(client_event->fd, tx, AUTH_REPLY_LEN, 0);
        if (sendlen == -1)
        {
            LOG_DEBUG("%s\n", strerror(errno));
        }
        clear_event(client_event);
    }
    free(uname);
    free(passwd);
}

static void accept_cb(struct event_data *server_event)
{
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t client_addr_len = sizeof(struct sockaddr_in);
    int client_fd = accept(server_event->fd, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_fd == -1)
    {
        LOG_DEBUG("%s\n", strerror(errno));
    }
    else
    {
        // fcntl(client_fd, F_SETFL, fcntl(client_fd, F_GETFL) | O_NONBLOCK);

        struct event_data *client_event = (struct event_data *)malloc(sizeof(struct event_data));
        client_event->addr = client_addr;
        client_event->fd = client_fd;
        client_event->cb = method_reply_cb;
        client_event->to = NULL;
        opt_event(epoll_fd, EPOLL_CTL_ADD, client_event, EPOLLIN);
    }
}

static void worker()
{
    server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(LISTEN_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    signal(SIGPIPE, SIG_IGN);

    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    // fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL) | O_NONBLOCK);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 5);
    LOG_INFO("listening port %d\n", LISTEN_PORT);

    epoll_fd = epoll_create(1024);

    // server_event
    struct event_data *server_event = (struct event_data *)malloc(sizeof(struct event_data));
    server_event->addr = server_addr;
    server_event->fd = server_fd;
    server_event->cb = accept_cb;
    server_event->to = NULL;

    opt_event(epoll_fd, EPOLL_CTL_ADD, server_event, EPOLLIN);

    epoll_start(epoll_fd, EPOLL_MAX_EVENTS, -1);
    close(server_fd);
    close(epoll_fd);
}

int main()
{
    /*
        for (int i = 0; i < MAX_WORKERS; i++)
        {
            pid_t pid = fork();
            if (pid == 0)
            {
                worker();
            }
            if (pid < 0)
            {
                fprintf(stderr, "%s(%d) %s\n", __FILE__, __LINE__, strerror(errno));
            }
        }

        while (wait(NULL) != 0)
        {
            break;
        }
    */
    worker();
    return 0;
}