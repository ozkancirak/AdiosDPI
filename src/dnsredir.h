#ifndef _DNSREDIR_H
#define _DNSREDIR_H
#include <stdint.h>

typedef struct conntrack_info {
    uint8_t  is_ipv6;
    uint32_t srcip[4];
    uint16_t srcport;
    uint32_t dstip[4];
    uint16_t dstport;
} conntrack_info_t;

inline static void ipv4_copy_addr(uint32_t dst[4], const uint32_t src[4]) {
    dst[0] = src[0];
    dst[1] = 0;
    dst[2] = 0;
    dst[3] = 0;
}

inline static void ipv6_copy_addr(uint32_t dst[4], const uint32_t src[4]) {
    dst[0] = src[0];
    dst[1] = src[1];
    dst[2] = src[2];
    dst[3] = src[3];
}

/* A DNS server queries are sent to. The port is in network byte order, as in the packets. */
typedef struct dns_server {
    uint32_t ip[4];     /* one 32-bit word for IPv4, four for IPv6 */
    uint16_t port;
} dns_server_t;

/*
 * The servers for one IP version: the first one, and a backup (NULL for none). The first is used
 * until a query it was given is asked again (the answer did not come); after that the backup takes
 * the queries for a minute and the first one is tried again. Call before the first packet.
 */
void dns_set_servers(uint8_t is_ipv6, const dns_server_t *first, const dns_server_t *backup);

/*
 * srcip and dstip: one 32-bit word for IPv4, four for IPv6. srcip and srcport are where the answer is
 * going to (the application); from_ip and from_port are the server it came from.
 */
int dns_handle_incoming(const uint32_t *srcip, const uint16_t srcport,
                        const char *packet_data, const UINT packet_dataLen,
                        conntrack_info_t *conn_info, const uint8_t is_ipv6,
                        const uint32_t *from_ip, const uint16_t from_port);

/* Returns TRUE for a DNS query that is to be sent to *target instead of where it was addressed. */
int dns_handle_outgoing(const uint32_t *srcip, const uint16_t srcport,
                        const uint32_t *dstip, const uint16_t dstport,
                        const char *packet_data, const UINT packet_dataLen,
                        const uint8_t is_ipv6, dns_server_t *target
                       );

void flush_dns_cache();
int dns_is_dns_packet(const char *packet_data, const UINT packet_dataLen, const int outgoing);
#endif
