#ifndef __SERVER_H__
#define __SERVER_H__

void method_reply_cb(struct event_data *client_event);
void socks_reply_cb(struct event_data *client_event);
void conn_relay(struct event_data *client_event, struct socks_request *socks_request);
void bind_relay(struct event_data *client_event, struct socks_request *socks_request);
void udp_relay(struct event_data *client_event, struct socks_request *socks_request);
void not_support(struct event_data *client_event, struct socks_request *socks_request, uint8_t rep);
void forword_data_cb(int dst_fd, int src_fd);
void tcp_relay_cb(struct event_data* event);
void udp_relay_cb(struct event_data* event);
void auth_cb(struct event_data* client_event);
void accept_cb(struct event_data *server_event);

#endif