/*
 * Holds back a ClientHello whose server name is not in its first segment.
 */

#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include "adiosdpi.h"
#include "reasm.h"
#include "tls.h"

#define HOLD_MS 1000
#define JOINED_MAX 16384        /* a TLS record is 16 KiB at most */

struct slot {
    char data[MAX_PACKET_SIZE];
    UINT len;
    WINDIVERT_ADDRESS addr;
};

/* Which connection a TCP packet belongs to and where in it. */
struct flow {
    int v6;
    UINT32 src[4], dst[4];
    UINT16 sport, dport;
    UINT32 seq;
    UINT payload_len;
    const char *payload;
};

enum { EMPTY, HELD, RELEASING };

static struct slot slots[2];            /* slots[0] is the held segment, slots[1] the one after it */
static struct flow held_flow;
static int state = EMPTY;
static int next_slot;
static ULONGLONG held_since;
static char joined[JOINED_MAX];
static struct reasm_result joined_result;

static int parse(const char *packet, UINT len, struct flow *flow) {
    PWINDIVERT_IPHDR ip;
    PWINDIVERT_IPV6HDR ip6;
    PWINDIVERT_TCPHDR tcp;
    PVOID payload;
    UINT payload_len;

    memset(flow, 0, sizeof(*flow));
    if (!WinDivertHelperParsePacket(packet, len, &ip, &ip6, NULL, NULL, NULL, &tcp, NULL,
                                    &payload, &payload_len, NULL, NULL) || !tcp || !payload)
        return FALSE;
    if (ip) {
        flow->src[0] = ip->SrcAddr;
        flow->dst[0] = ip->DstAddr;
    } else if (ip6) {
        flow->v6 = 1;
        memcpy(flow->src, ip6->SrcAddr, sizeof(flow->src));
        memcpy(flow->dst, ip6->DstAddr, sizeof(flow->dst));
    } else {
        return FALSE;
    }
    flow->sport = tcp->SrcPort;
    flow->dport = tcp->DstPort;
    flow->seq = ntohl(tcp->SeqNum);
    flow->payload = payload;
    flow->payload_len = payload_len;
    return TRUE;
}

int reasm_hold(const char *packet, UINT len, const WINDIVERT_ADDRESS *addr) {
    if (state != EMPTY || len > sizeof(slots[0].data))
        return FALSE;
    memcpy(slots[0].data, packet, len);
    slots[0].len = len;
    slots[0].addr = *addr;
    if (!parse(slots[0].data, len, &held_flow))
        return FALSE;
    state = HELD;
    held_since = GetTickCount64();
    return TRUE;
}

int reasm_join(const char *packet, UINT len, const WINDIVERT_ADDRESS *addr) {
    struct flow flow;
    UINT total;

    if (state != HELD || len > sizeof(slots[1].data) || !parse(packet, len, &flow))
        return FALSE;
    if (flow.v6 != held_flow.v6 || flow.sport != held_flow.sport || flow.dport != held_flow.dport ||
        memcmp(flow.src, held_flow.src, sizeof(flow.src)) != 0 ||
        memcmp(flow.dst, held_flow.dst, sizeof(flow.dst)) != 0 ||
        flow.seq != held_flow.seq + held_flow.payload_len)
        return FALSE;

    memset(&joined_result, 0, sizeof(joined_result));
    joined_result.known = 1;
    total = held_flow.payload_len + flow.payload_len;
    if (total <= JOINED_MAX) {
        memcpy(joined, held_flow.payload, held_flow.payload_len);
        memcpy(joined + held_flow.payload_len, flow.payload, flow.payload_len);
        joined_result.sni_ok = tls_extract_sni(joined, total, &joined_result.host, &joined_result.host_len);
    }
    memcpy(slots[1].data, packet, len);
    slots[1].len = len;
    slots[1].addr = *addr;
    state = RELEASING;
    next_slot = 0;
    return TRUE;
}

int reasm_next(char *packet, UINT size, UINT *len, WINDIVERT_ADDRESS *addr, struct reasm_result *result) {
    struct slot *slot;

    if (state != RELEASING || slots[next_slot].len > size)
        return FALSE;
    slot = &slots[next_slot];
    memcpy(packet, slot->data, slot->len);
    *len = slot->len;
    *addr = slot->addr;
    if (next_slot == 0)
        *result = joined_result;        /* only the first segment is told what the name is */
    if (++next_slot == 2)
        state = EMPTY;
    return TRUE;
}

void reasm_expire(HANDLE handle) {
    if (state == HELD && GetTickCount64() - held_since >= HOLD_MS) {
        WinDivertSend(handle, slots[0].data, slots[0].len, NULL, &slots[0].addr);
        state = EMPTY;
    }
}
