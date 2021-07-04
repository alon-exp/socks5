#ifndef __PROTO_H__
#define __PROTO_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

// socks5 version
#define SOCKS5_VERSION 0x05
#define VERSION SOCKS5_VERSION

// methods
#define NO_AUTHENTICATION_REQUIRED 0x00
#define GSSAPI 0x01
#define USERNAME_PASSWORD 0x02
#define NO_ACCEPTABLE_METHODS 0xff

// requests
// cmd
#define CONNECT 0x01
#define BIND 0x02
#define UDP_ASSOCIATE 0x03

// replies
// rep
#define SUCCEEDED 0x00
#define GENERAL_SOCKS_SERVER_FAILURE 0x01
#define CONNECTION_NOT_ALLOWED_BY_RULESET 0x02
#define NETWORK_UNREACHABLE 0x03
#define HOST_UNREACHABLE 0x04
#define CONNECTION_REFUSED 0x05
#define TTL_EXPIRED 0x06
#define COMMAND_NOT_SUPPORTED 0x07
#define ADDRESS_TYPE_NOT_SUPPORTED 0x08

// limitation of length
#define MAX_METHOD_REQUEST_LEN 0x101
#define MIN_METHOD_REQUEST_LEN 0x003
#define METHOD_REPLY_LEN 0x002
#define MAX_METHOD_REPLY_LEN METHOD_REPLY_LEN
#define MIN_METHOD_REPLY_LEN METHOD_REPLY_LEN
#define MAX_SOCKS_REQUEST_LEN 0x103
#define MIN_SOCKS_REUQEST_LEN 0x00A
#define MAX_AUTH_REQUEST_LEN 513
#define MIN_AUTH_REQUEST_LEN 5
#define AUTH_REPLY_LEN 2
#define MAX_AUTH_REPLY_LEN AUTH_REPLY_LEN
#define MIN_AUTH_REPLY_LEN AUTH_REPLY_LEN
#define MAX_SOCKS_REPLY_LEN MAX_SOCKS_REQUEST_LEN
#define MIN_SOCKS_REPLY_LEN MIN_SOCKS_REUQEST_LEN

// reserved
#define RESERVED 0x00
#define UDP_RESERVED 0x0000

// frag
#define UDP_FRAG 0x00 

// atyp
#define IPV4 0x01
#define DOMAIN 0x03
#define IPV6 0x04

#define SOCKS5_METHOD_REQUEST 0x01
#define SOCKS5_SOCKS_REQUEST 0x02

// auth
#define AUTH_VERSION 0x01
#define AUTH_SUCCESS 0x00
#define AUTH_FAILURE 0xff

// version identifier/method selection message
struct method_request
{
    uint8_t ver;
    uint8_t nmethods;
    uint8_t methods[];
};

struct method_reply
{
    uint8_t ver;
    uint8_t method;
};

union dst_or_bnd
{
    struct
    {
        in_addr_t addr;
        in_port_t port;
    } ipv4;
    struct
    {
        uint8_t len;
        uint8_t str[];
    } domain;
    struct
    {
        uint8_t addr[16];
        in_port_t port;
    } ipv6;
};

struct socks_request
{
    uint8_t ver;
    uint8_t cmd;
    uint8_t rsv;
    uint8_t atyp;
    union dst_or_bnd dst;
};

struct socks_reply
{
    uint8_t ver;
    uint8_t rep;
    uint8_t rsv;
    uint8_t atyp;
    union dst_or_bnd bnd;
};

struct socks_udp_header
{
    uint16_t rsv;
    uint8_t frag;
    uint8_t atyp;
    union dst_or_bnd dst;
};

struct auth_request_ver
{
    uint8_t ver;
};

struct auth_request_uname
{
    uint8_t ulen;
    uint8_t uname[];
};

struct auth_request_passwd
{
    uint8_t plen;
    uint8_t passwd[];
};

struct auth_reply
{
    uint8_t ver;
    uint8_t status;
};

char *add_socks_udp_header(struct socks_udp_header *socks_udp_header, uint8_t *payload, in_addr_t remote_udp_addr, in_port_t remote_udp_port, int *add_len);
char *del_socks_udp_header(struct socks_udp_header *socks_udp_header, uint8_t *payload, int *del_len);
bool check_validity(uint8_t *rx, int recvlen, int stage);
bool check_method(uint8_t *rx, uint8_t method);

#endif