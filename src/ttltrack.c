/**
 * TCP (TTL) Connection Tracker for AdiosDPI
 *
 * Monitors SYN/ACK only, to extract the TTL value of the remote server.
 *
 */

#include <windows.h>
#include <time.h>
#include <stdio.h>
#include <math.h>
#include "adiosdpi.h"
#include "ttltrack.h"

/* key ('4' for IPv4 or '6' for IPv6 + srcip[16] + dstip[16] + srcport[2] + dstport[2]) */
#define TCP_CONNRECORD_KEY_LEN 37

#define TCP_CLEANUP_INTERVAL_SEC 30

/*
 * A fixed open-addressing table: the packet path never allocates and a lookup
 * touches one line of memory. The table is far bigger than the number of
 * connections that are waiting for their first outbound packet.
 */
#define TCP_TABLE_SLOTS 512
#define TCP_TABLE_PROBES 16

typedef struct tcp_connrecord {
    /* key ('4' for IPv4 or '6' for IPv6 + srcip[16] + dstip[16] + srcport[2] + dstport[2]) */
    char key[TCP_CONNRECORD_KEY_LEN];
    time_t time;         /* time when this record was added */
    uint16_t ttl;
    uint8_t used;
} tcp_connrecord_t;

static time_t last_cleanup = 0;
static tcp_connrecord_t conntrack[TCP_TABLE_SLOTS];

inline static void fill_key_data(char *key, const uint8_t is_ipv6, const uint32_t srcip[4],
                    const uint32_t dstip[4], const uint16_t srcport, const uint16_t dstport)
{
    unsigned int offset = 0;

    if (is_ipv6) {
        *(uint8_t*)(key) = '6';
        offset += sizeof(uint8_t);
        ipv6_copy_addr((uint32_t*)(key + offset), srcip);
        offset += sizeof(uint32_t) * 4;
        ipv6_copy_addr((uint32_t*)(key + offset), dstip);
        offset += sizeof(uint32_t) * 4;
    }
    else {
        *(uint8_t*)(key) = '4';
        offset += sizeof(uint8_t);
        ipv4_copy_addr((uint32_t*)(key + offset), srcip);
        offset += sizeof(uint32_t) * 4;
        ipv4_copy_addr((uint32_t*)(key + offset), dstip);
        offset += sizeof(uint32_t) * 4;
    }

    *(uint16_t*)(key + offset) = srcport;
    offset += sizeof(srcport);
    *(uint16_t*)(key + offset) = dstport;
    offset += sizeof(dstport);
}

inline static void fill_data_from_key(uint8_t *is_ipv6, uint32_t srcip[4], uint32_t dstip[4],
                                     uint16_t *srcport, uint16_t *dstport, const char *key)
{
    unsigned int offset = 0;

    if (key[0] == '6') {
        *is_ipv6 = 1;
        offset += sizeof(uint8_t);
        ipv6_copy_addr(srcip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
        ipv6_copy_addr(dstip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
    }
    else {
        *is_ipv6 = 0;
        offset += sizeof(uint8_t);
        ipv4_copy_addr(srcip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
        ipv4_copy_addr(dstip, (uint32_t*)(key + offset));
        offset += sizeof(uint32_t) * 4;
    }
    *srcport = *(uint16_t*)(key + offset);
    offset += sizeof(*srcport);
    *dstport = *(uint16_t*)(key + offset);
    offset += sizeof(*dstport);
}

inline static void construct_key(const uint32_t srcip[4], const uint32_t dstip[4],
                                 const uint16_t srcport, const uint16_t dstport,
                                 char *key, const uint8_t is_ipv6)
{
    if (key)
        fill_key_data(key, is_ipv6, srcip, dstip, srcport, dstport);
}

inline static void deconstruct_key(const char *key, const tcp_connrecord_t *connrecord,
                                   tcp_conntrack_info_t *conn_info)
{
    if (key && conn_info) {
        fill_data_from_key(&conn_info->is_ipv6,
                           conn_info->srcip, conn_info->dstip,
                           &conn_info->srcport, &conn_info->dstport,
                           key);

        conn_info->ttl = (uint8_t)connrecord->ttl;
    }
}

static unsigned int table_hash(const char *key) {
    uint32_t h = 2166136261u;
    unsigned int i;

    for (i = 0; i < TCP_CONNRECORD_KEY_LEN; i++)
        h = (h ^ (uint8_t)key[i]) * 16777619u;
    return h % TCP_TABLE_SLOTS;
}

static tcp_connrecord_t *find_record(const char *key) {
    unsigned int home = table_hash(key), i;

    for (i = 0; i < TCP_TABLE_PROBES; i++) {
        tcp_connrecord_t *rec = &conntrack[(home + i) % TCP_TABLE_SLOTS];

        if (!rec->used)
            return NULL;
        if (memcmp(rec->key, key, TCP_CONNRECORD_KEY_LEN) == 0)
            return rec;
    }
    return NULL;
}

static tcp_connrecord_t *insert_record(const char *key) {
    unsigned int home = table_hash(key), i;

    for (i = 0; i < TCP_TABLE_PROBES; i++) {
        tcp_connrecord_t *rec = &conntrack[(home + i) % TCP_TABLE_SLOTS];

        if (!rec->used) {
            memset(rec, 0, sizeof(*rec));
            memcpy(rec->key, key, TCP_CONNRECORD_KEY_LEN);
            rec->used = 1;
            return rec;
        }
    }
    return NULL;
}

/* Linear probing: after a removal the entries behind it move back, so lookups still stop at an empty slot. */
static void remove_record(tcp_connrecord_t *rec) {
    unsigned int i = (unsigned int)(rec - conntrack), j = i;

    for (;;) {
        unsigned int home;

        j = (j + 1) % TCP_TABLE_SLOTS;
        if (!conntrack[j].used)
            break;
        home = table_hash(conntrack[j].key);
        if (i < j ? (home <= i || home > j) : (home <= i && home > j)) {
            conntrack[i] = conntrack[j];
            i = j;
        }
    }
    conntrack[i].used = 0;
}

static int check_get_tcp_conntrack_key(const char *key, tcp_connrecord_t **connrecord) {
    tcp_connrecord_t *rec = find_record(key);

    if (rec) {
        if (connrecord)
            *connrecord = rec;
        debug("check_get_tcp_conntrack_key found key\n");
        return TRUE;
    }
    debug("check_get_tcp_conntrack_key key not found\n");
    return FALSE;
}

static int add_tcp_conntrack(const uint32_t srcip[4], const uint32_t dstip[4],
                             const uint16_t srcport, const uint16_t dstport,
                             const uint8_t is_ipv6, const uint8_t ttl
                            )
{
    char key[TCP_CONNRECORD_KEY_LEN];
    tcp_connrecord_t *rec;

    if (!(srcip && srcport && dstip && dstport))
        return FALSE;

    construct_key(srcip, dstip, srcport, dstport, key, is_ipv6);
    if (check_get_tcp_conntrack_key(key, NULL)) {
        debug("Not added TCP conntrack %u:%hu - %u:%hu\n", srcip[0], ntohs(srcport), dstip[0], ntohs(dstport));
        return FALSE;
    }
    rec = insert_record(key);
    if (!rec)
        return FALSE;
    rec->time = time(NULL);
    rec->ttl = ttl;
    debug("Added TCP conntrack %u:%hu - %u:%hu\n", srcip[0], ntohs(srcport), dstip[0], ntohs(dstport));
    return TRUE;
}

static void tcp_cleanup(void) {
    time_t now;
    unsigned int i;

    if (last_cleanup == 0) {
        last_cleanup = time(NULL);
        return;
    }

    now = time(NULL);
    if (difftime(now, last_cleanup) < TCP_CLEANUP_INTERVAL_SEC)
        return;
    last_cleanup = now;

    for (i = 0; i < TCP_TABLE_SLOTS; i++)
        if (conntrack[i].used && difftime(now, conntrack[i].time) >= TCP_CLEANUP_INTERVAL_SEC)
            remove_record(&conntrack[i]);
}

int tcp_handle_incoming(const uint32_t *srcip, const uint32_t *dstip,
                        uint16_t srcport, uint16_t dstport,
                        uint8_t is_ipv6, uint8_t ttl)
{
    tcp_cleanup();

    debug("trying to add TCP srcport = %hu, dstport = %hu\n", ntohs(srcport), ntohs(dstport));
    return add_tcp_conntrack(srcip, dstip, srcport, dstport, is_ipv6, ttl);
}

int tcp_handle_outgoing(const uint32_t *srcip, const uint32_t *dstip,
                        uint16_t srcport, uint16_t dstport,
                        tcp_conntrack_info_t *conn_info,
                        uint8_t is_ipv6)
{
    char key[TCP_CONNRECORD_KEY_LEN];
    tcp_connrecord_t *rec;

    if (!conn_info)
        return FALSE;

    tcp_cleanup();
    construct_key(dstip, srcip, dstport, srcport, key, is_ipv6);
    rec = find_record(key);
    if (rec) {
        /* Connection exists in conntrack, moving on */
        deconstruct_key(key, rec, conn_info);
        remove_record(rec);
        debug("____tcp_handle_outgoing TRUE: srcport = %hu\n", ntohs(srcport));
        return TRUE;
    }

    debug("____tcp_handle_outgoing FALSE: srcport = %hu\n", ntohs(srcport));
    return FALSE;
}

int tcp_get_auto_ttl(const uint8_t ttl, const uint8_t autottl1,
                     const uint8_t autottl2, const uint8_t minhops,
                     const uint8_t maxttl) {
    uint8_t nhops = 0;
    uint8_t ttl_of_fake_packet = 0;

    if (ttl > 98 && ttl < 128) {
        nhops = 128 - ttl;
    }
    else if (ttl > 34 && ttl < 64) {
        nhops = 64 - ttl;
    }
    else {
        return 0;
    }

    if (nhops <= autottl1 || nhops < minhops) {
        return 0;
    }

    ttl_of_fake_packet = nhops - autottl2;
    if (ttl_of_fake_packet < autottl2 && nhops <= 9) {
        ttl_of_fake_packet = nhops - autottl1 - trunc((autottl2 - autottl1) * ((float)nhops/10));
    }

    if (maxttl && ttl_of_fake_packet > maxttl) {
        ttl_of_fake_packet = maxttl;
    }

    return ttl_of_fake_packet;
}
