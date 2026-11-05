/*
 * DNS UDP Connection Tracker for AdiosDPI
 *
 * This is a simple connection tracker for DNS UDP data.
 * It's not a proper one. The caveats as follows:
 *    * Uses only source IP address and port as a hash key;
 *    * One-shot only. Removes conntrack record as soon as gets the reply;
 *    * Remembers which of the (up to two) servers a query went to, and moves to the backup when
 *      the same query is sent again without an answer;
 *    * Does not properly parse DNS request and response, only checks some bytes;
 *
 * But anyway, it works fine for DNS.
 */

#include <windows.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "adiosdpi.h"
#include "dnsredir.h"
#include "utils/uthash.h"

/* key ('4' for IPv4 or '6' for IPv6 + srcip[16] + srcport[2]) */
#define UDP_CONNRECORD_KEY_LEN 19

#define DNS_CLEANUP_INTERVAL_SEC 30

/* HACK!
 * uthash uses strlen() for HASH_FIND_STR.
 * We have null bytes in our key, so we can't use strlen()
 * And since it's always UDP_CONNRECORD_KEY_LEN bytes long,
 * we don't need to use any string function to determine length.
 */
#undef uthash_strlen
#define uthash_strlen(s) UDP_CONNRECORD_KEY_LEN

typedef struct udp_connrecord {
    /* key ('4' for IPv4 or '6' for IPv6 + srcip[16] + srcport[2]) */
    char key[UDP_CONNRECORD_KEY_LEN];
    time_t time;         /* time when this record was added */
    uint32_t dstip[4];
    uint16_t dstport;
    ULONGLONG sent;      /* GetTickCount64() when the query was last sent */
    uint16_t id;         /* DNS transaction id, as in the packet */
    uint8_t server;      /* which server it went to: 0 the first, 1 the backup */
    UT_hash_handle hh;   /* makes this structure hashable */
} udp_connrecord_t;

static time_t last_cleanup = 0;
static udp_connrecord_t *conntrack = NULL;

/* A server that did not answer is left alone for this long, then it is tried again. */
#define DNS_AVOID_MS 60000

static struct {
    dns_server_t server[2];
    int count;                  /* 0: not used, 1: only the first, 2: first and backup */
    ULONGLONG failed[2];        /* when each last failed to answer, 0 if never or answered since */
    ULONGLONG alive[2];         /* when each last answered, 0 if never */
} servers[2];                   /* [0] IPv4, [1] IPv6 */

void dns_set_servers(uint8_t is_ipv6, const dns_server_t *first, const dns_server_t *backup)
{
    int f = is_ipv6 ? 1 : 0;

    servers[f].server[0] = *first;
    servers[f].count = 1;
    if (backup) {
        servers[f].server[1] = *backup;
        servers[f].count = 2;
    }
    servers[f].failed[0] = servers[f].failed[1] = 0;
    servers[f].alive[0] = servers[f].alive[1] = 0;
}

/*
 * The first server, unless it failed lately and the backup did not. When both failed lately, the one
 * that answered last; if neither ever did, the one that failed longer ago, so a query that nobody
 * answers goes back and forth between them.
 */
static int choose_server(int f, ULONGLONG now)
{
    int first_bad, backup_bad;

    if (servers[f].count < 2)
        return 0;
    first_bad = servers[f].failed[0] && now - servers[f].failed[0] < DNS_AVOID_MS;
    backup_bad = servers[f].failed[1] && now - servers[f].failed[1] < DNS_AVOID_MS;
    if (first_bad && backup_bad) {
        if (servers[f].alive[0] != servers[f].alive[1])
            return servers[f].alive[1] > servers[f].alive[0];
        return servers[f].failed[0] <= servers[f].failed[1] ? 0 : 1;
    }
    return first_bad;
}

void flush_dns_cache() {
    INT_PTR WINAPI (*DnsFlushResolverCache)();

    HMODULE dnsapi = LoadLibrary("dnsapi.dll");
    if (dnsapi == NULL)
    {
        printf("Can't load dnsapi.dll to flush DNS cache!\n");
        exit(EXIT_FAILURE);
    }

    DnsFlushResolverCache = GetProcAddress(dnsapi, "DnsFlushResolverCache");
    if (DnsFlushResolverCache == NULL || !DnsFlushResolverCache())
        printf("Can't flush DNS cache!");
    FreeLibrary(dnsapi);
}

inline static void fill_key_data(char *key, const uint8_t is_ipv6, const uint32_t srcip[4],
                          const uint16_t srcport)
{
    if (is_ipv6) {
        *(uint8_t*)(key) = '6';
        ipv6_copy_addr((uint32_t*)(key + sizeof(uint8_t)), srcip);
    }
    else {
        *(uint8_t*)(key) = '4';
        ipv4_copy_addr((uint32_t*)(key + sizeof(uint8_t)), srcip);
    }

    *(uint16_t*)(key + sizeof(uint8_t) + sizeof(uint32_t) * 4) = srcport;
}

inline static void fill_data_from_key(uint8_t *is_ipv6, uint32_t srcip[4], uint16_t *srcport,
                                      const char *key)
{
    if (key[0] == '6') {
        *is_ipv6 = 1;
        ipv6_copy_addr(srcip, (uint32_t*)(key + sizeof(uint8_t)));
    }
    else {
        *is_ipv6 = 0;
        ipv4_copy_addr(srcip, (uint32_t*)(key + sizeof(uint8_t)));
    }
    *srcport = *(uint16_t*)(key + sizeof(uint8_t) + sizeof(uint32_t) * 4);
}

inline static void construct_key(const uint32_t srcip[4], const uint16_t srcport,
                                 char *key, const uint8_t is_ipv6)
{
    debug("Construct key enter\n");
    if (key) {
        debug("Constructing key\n");
        fill_key_data(key, is_ipv6, srcip, srcport);
    }
    debug("Construct key end\n");
}

inline static void deconstruct_key(const char *key, const udp_connrecord_t *connrecord,
                                   conntrack_info_t *conn_info)
{
    debug("Deconstruct key enter\n");
    if (key && conn_info) {
        debug("Deconstructing key\n");
        fill_data_from_key(&conn_info->is_ipv6, conn_info->srcip,
                           &conn_info->srcport, key);

        if (conn_info->is_ipv6)
            ipv6_copy_addr(conn_info->dstip, connrecord->dstip);
        else
            ipv4_copy_addr(conn_info->dstip, connrecord->dstip);

        conn_info->dstport = connrecord->dstport;
    }
    debug("Deconstruct key end\n");
}

static int check_get_udp_conntrack_key(const char *key, udp_connrecord_t **connrecord) {
    udp_connrecord_t *tmp_connrecord = NULL;
    if (!conntrack) return FALSE;

    HASH_FIND_STR(conntrack, key, tmp_connrecord);
    if (tmp_connrecord) {
        if (connrecord)
            *connrecord = tmp_connrecord;
        debug("check_get_udp_conntrack_key found key\n");
        return TRUE;
    }
    debug("check_get_udp_conntrack_key key not found\n");
    return FALSE;
}

static int add_udp_conntrack(const uint32_t srcip[4], const uint16_t srcport,
                             const uint32_t dstip[4], const uint16_t dstport,
                             const uint8_t is_ipv6, const uint16_t id, const int server,
                             const ULONGLONG now, udp_connrecord_t **added
                            )
{
    if (!(srcip && srcport && dstip && dstport))
        return FALSE;

    udp_connrecord_t *tmp_connrecord = malloc(sizeof(udp_connrecord_t));
    if (!tmp_connrecord)
        return FALSE;
    construct_key(srcip, srcport, tmp_connrecord->key, is_ipv6);

    if (!check_get_udp_conntrack_key(tmp_connrecord->key, NULL)) {
        tmp_connrecord->time = time(NULL);

        if (is_ipv6) {
            ipv6_copy_addr(tmp_connrecord->dstip, dstip);
        }
        else {
            ipv4_copy_addr(tmp_connrecord->dstip, dstip);
        }
        tmp_connrecord->dstport = dstport;
        tmp_connrecord->sent = now;
        tmp_connrecord->id = id;
        tmp_connrecord->server = (uint8_t)server;
        HASH_ADD_STR(conntrack, key, tmp_connrecord);
        *added = tmp_connrecord;
        debug("Added UDP conntrack\n");
        return TRUE;
    }
    debug("Not added UDP conntrack\n");
    free(tmp_connrecord);
    return FALSE;
}

static void dns_cleanup() {
    udp_connrecord_t *tmp_connrecord, *tmp_connrecord2 = NULL;

    if (last_cleanup == 0) {
        last_cleanup = time(NULL);
        return;
    }

    if (difftime(time(NULL), last_cleanup) >= DNS_CLEANUP_INTERVAL_SEC) {
        last_cleanup = time(NULL);

        HASH_ITER(hh, conntrack, tmp_connrecord, tmp_connrecord2) {
            if (difftime(last_cleanup, tmp_connrecord->time) >= DNS_CLEANUP_INTERVAL_SEC) {
                HASH_DEL(conntrack, tmp_connrecord);
                free(tmp_connrecord);
            }
        }
    }
}

int dns_is_dns_packet(const char *packet_data, const UINT packet_dataLen, const int outgoing) {
    if (packet_dataLen < 16) return FALSE;

    /* A request has no answer and no authority records (bytes 6 to 9). Additional records may carry EDNS. */
    if (outgoing && (ntohs(*(const uint16_t*)(packet_data + 2)) & 0xFA00) == 0 &&
        !(packet_data[6] | packet_data[7] | packet_data[8] | packet_data[9])) {
        return TRUE;
    }
    else if (!outgoing &&
        (ntohs(*(const uint16_t*)(packet_data + 2)) & 0xF800) == 0x8000) {
        return TRUE;
    }
    return FALSE;
}

int dns_handle_outgoing(const uint32_t *srcip, const uint16_t srcport,
                        const uint32_t *dstip, const uint16_t dstport,
                        const char *packet_data, const UINT packet_dataLen,
                        const uint8_t is_ipv6, dns_server_t *target)
{
    char key[UDP_CONNRECORD_KEY_LEN];
    udp_connrecord_t *record = NULL;
    int f = is_ipv6 ? 1 : 0;
    uint16_t id;
    ULONGLONG now;

    if (packet_dataLen < 16 || !target || !servers[f].count)
        return FALSE;

    dns_cleanup();

    if (!dns_is_dns_packet(packet_data, packet_dataLen, 1)) {
        debug("____dns_handle_outgoing FALSE: srcport = %hu, dstport = %hu\n", ntohs(srcport), ntohs(dstport));
        return FALSE;
    }
    /* Looks like DNS request */
    debug("trying to add srcport = %hu, dstport = %hu\n", ntohs(srcport), ntohs(dstport));
    /* A query from a link-local address (Windows asking the router's own IPv6 address) cannot be answered
     * by a server somewhere else. It is dropped; Windows asks the router's other addresses too. */
    if (is_ipv6 && ((const uint8_t *)srcip)[0] == 0xfe && (((const uint8_t *)srcip)[1] & 0xc0) == 0x80)
        return FALSE;
    now = GetTickCount64();
    memcpy(&id, packet_data, sizeof(id));

    construct_key(srcip, srcport, key, is_ipv6);
    if (check_get_udp_conntrack_key(key, &record)) {
        /* The same query again from the same socket: no answer came (Windows asks again after a few
         * seconds, and it asks every server it knows, so this may be another way to the same query).
         * Another query on a socket that is still waiting is dropped, as it always was. */
        if (record->id != id)
            return FALSE;
        if (servers[f].count == 2) {
            servers[f].failed[record->server] = now;
            record->server = (uint8_t)choose_server(f, now);
        }
        record->sent = now;
        record->time = time(NULL);
        *target = servers[f].server[record->server];
        return TRUE;
    }
    if (!add_udp_conntrack(srcip, srcport, dstip, dstport, is_ipv6, id, choose_server(f, now), now, &record))
        return FALSE;
    *target = servers[f].server[record->server];
    return TRUE;
}

int dns_handle_incoming(const uint32_t *srcip, const uint16_t srcport,
                        const char *packet_data, const UINT packet_dataLen,
                        conntrack_info_t *conn_info, const uint8_t is_ipv6,
                        const uint32_t *from_ip, const uint16_t from_port)
{
    char key[UDP_CONNRECORD_KEY_LEN];
    udp_connrecord_t *tmp_connrecord = NULL;
    int f = is_ipv6 ? 1 : 0, s;

    if (packet_dataLen < 16 || !conn_info)
        return FALSE;

    dns_cleanup();

    if (dns_is_dns_packet(packet_data, packet_dataLen, 0)) {
        /* Looks like DNS response */
        construct_key(srcip, srcport, key, is_ipv6);
        if (check_get_udp_conntrack_key(key, &tmp_connrecord) && tmp_connrecord) {
            /* Connection exists in conntrack, moving on. The server the answer came from is alive: it is
             * judged by the address on the answer, not by where the query was last sent. */
            for (s = 0; s < servers[f].count; s++)
                if (servers[f].server[s].port == from_port &&
                    memcmp(servers[f].server[s].ip, from_ip, is_ipv6 ? 16 : 4) == 0) {
                    servers[f].failed[s] = 0;
                    servers[f].alive[s] = GetTickCount64();
                }
            deconstruct_key(key, tmp_connrecord, conn_info);
            HASH_DEL(conntrack, tmp_connrecord);
            free(tmp_connrecord);
            return TRUE;
        }
    }
    debug("____dns_handle_incoming FALSE: srcport = %hu\n", ntohs(srcport));
    return FALSE;
}
