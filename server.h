#ifndef __SERVER_H__
#define __SERVER_H__

static void method_reply_cb(struct event_data *client_event);
static void socks_reply_cb(struct event_data *client_event);
static void conn_relay(struct event_data *client_event, struct socks_request *socks_request, in_addr_t conn_addr);
static void bind_relay(struct event_data *client_event, struct socks_request *socks_request);
static void udp_relay(struct event_data *client_event, struct socks_request *socks_request);
static void not_support(struct event_data *client_event, struct socks_request *socks_request, uint8_t rep);
static void forword_data_cb(int dst_fd, int src_fd);
static void tcp_relay_cb(struct event_data *event);
static void udp_relay_cb(struct event_data *event);
static void auth_cb(struct event_data *client_event);
static void accept_cb(struct event_data *server_event);

#endif