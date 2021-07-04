#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

void get_local_sockaddr(int fd, in_addr_t *addr, in_port_t *port);
void get_peer_sockaddr(int fd, in_addr_t *addr, in_port_t *port);
in_addr_t resolve_domain(char *domain, int *atyp);

#endif