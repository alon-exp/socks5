#include "proto.h"

char *add_socks_udp_header(struct socks_udp_header *socks_udp_header, uint8_t *payload, in_addr_t remote_udp_addr, in_port_t remote_udp_port, int *add_len)
{
    // ipv4 only
    socks_udp_header->rsv = UDP_RESERVED;
    socks_udp_header->frag = UDP_FRAG;
    socks_udp_header->atyp = IPV4;
    socks_udp_header->dst.ipv4.addr = remote_udp_addr;
    socks_udp_header->dst.ipv4.port = remote_udp_port;

    memcpy(socks_udp_header + 10, payload, strlen(payload));
    return (char *)socks_udp_header;
}

char *del_socks_udp_header(struct socks_udp_header *socks_udp_header, uint8_t *payload, int *del_len)
{
    int socks_udp_header_len = 0;
    if (socks_udp_header->atyp == IPV4)
    {
        socks_udp_header_len = 10;
    }
    else if (socks_udp_header->atyp == DOMAIN)
    {
        socks_udp_header_len = 7 + socks_udp_header->dst.domain.len;
    }
    *del_len = socks_udp_header_len;
    return (char *)socks_udp_header + socks_udp_header_len;
}

bool check_validity(uint8_t *rx, int recvlen, int stage)
{
    if (stage == SOCKS5_METHOD_REQUEST)
    {
        struct method_request *method_request = (struct method_request *)rx;
        if (recvlen < MIN_METHOD_REQUEST_LEN || recvlen > MAX_METHOD_REQUEST_LEN)
            return false;
        if (method_request->ver != SOCKS5_VERSION)
            return false;
        if (method_request->nmethods != recvlen - 2)
            return false;
        return true;
    }
    else if (stage == SOCKS5_SOCKS_REQUEST)
    {
        struct socks_request *socks_request = (struct socks_request *)rx;
        if (recvlen < MIN_SOCKS_REUQEST_LEN || recvlen > MAX_SOCKS_REQUEST_LEN)
            return false;
        if (socks_request->ver != SOCKS5_VERSION)
            return false;
        if (socks_request->rsv != RESERVED)
            return false;
        if (socks_request->cmd < 0x01 || socks_request->cmd > 0x03)
            return false;
        if (socks_request->atyp == IPV4)
        {
            if (recvlen - 4 != 6)
            {
                return false;
            }
        }
        else if (socks_request->atyp == IPV6)
        {
            if (recvlen - 4 != 18)
            {
                return false;
            }
        }
        else if (socks_request->atyp == DOMAIN)
        {
            if (recvlen - 5 != 2 + socks_request->dst.domain.len)
            {
                return false;
            }
        }
        else
        {
            return false;
        }
        return true;
    }
    return false;
}

bool check_method(uint8_t *rx, uint8_t method)
{
    struct method_request *method_request = (struct method_request *)rx;
    uint8_t *methods = (uint8_t *)malloc(method_request->nmethods);
    memcpy(methods, method_request->methods, method_request->nmethods);
    for (int i = 0; i < method_request->nmethods; i++)
    {
        if (methods[i] == method)
        {
            return true;
        }
    }
    return false;
}
