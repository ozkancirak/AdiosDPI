#ifndef _DNSCHECK_H
#define _DNSCHECK_H
#include <stdint.h>

/*
 * Asks the system resolver and a plain DNS server for the IPv4 addresses of
 * domain, prints both answers and says whether the system one looks poisoned.
 * server and port are in network byte order; 0 means 77.88.8.8 port 1253.
 *
 * Returns 0 when no poisoning was found (the answers agree, or differ the way a
 * CDN makes them differ), 1 when the system resolver gives a block page address
 * or nothing at all, 2 when the DNS server gave no answer.
 */
int dns_check(const char *domain, uint32_t server, uint16_t port);

#endif
