#include "util.h"
#include "lib.h"

void get_local_sockaddr(int fd, in_addr_t *addr, in_port_t *port)
{
    struct sockaddr_in local_sockaddr;
    // memset(&local_sockaddr, '\0', sizeof(local_sockaddr));
    socklen_t local_sockaddr_len = sizeof(struct sockaddr_in);
    getsockname(fd, (struct sockaddr *)&local_sockaddr, &local_sockaddr_len);
    *addr = local_sockaddr.sin_addr.s_addr;
    *port = local_sockaddr.sin_port;
}

void get_peer_sockaddr(int fd, in_addr_t *addr, in_port_t *port)
{
    struct sockaddr_in peer_sockaddr;
    // memset(&peer_sockaddr, '\0', sizeof(peer_sockaddr));
    socklen_t peer_sockaddr_len = sizeof(struct sockaddr_in);
    getpeername(fd, (struct sockaddr *)&peer_sockaddr, &peer_sockaddr_len);
    *addr = peer_sockaddr.sin_addr.s_addr;
    *port = peer_sockaddr.sin_port;
}

in_addr_t resolve_domain(char *domain, int *atyp)
{
    struct hostent *host = gethostbyname(domain);
    if (host == NULL)
    {
        return 0U;
    }
    *atyp = host->h_addrtype;
    return *(in_addr_t *)host->h_addr;
}
