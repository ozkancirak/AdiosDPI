#ifndef _SENDSPLIT_H
#define _SENDSPLIT_H

#include <winsock2.h>
#include <windows.h>
#include "windivert.h"

/* Queues one packet to be sent with the others of the batch. Defined in adiosdpi.c. */
void queue_tx(HANDLE w_filter, const char *packet, UINT len, const WINDIVERT_ADDRESS *addr);

void send_native_fragment(HANDLE w_filter, WINDIVERT_ADDRESS addr,
                          char *packet, UINT packetLen, PVOID packet_data,
                          UINT packet_dataLen, int packet_v4, int packet_v6,
                          PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr,
                          PWINDIVERT_TCPHDR ppTcpHdr,
                          unsigned int fragment_size, int step);

void send_split(HANDLE w_filter, WINDIVERT_ADDRESS addr,
                char *packet, UINT packetLen, PVOID packet_data, UINT packet_dataLen,
                int packet_v4, int packet_v6,
                PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr, PWINDIVERT_TCPHDR ppTcpHdr,
                const unsigned int *cuts, int count, unsigned int seqovl, int reverse);

/*
 * Cuts the one TLS record of a ClientHello into two records at data offset cut (6 or more: the
 * record header is 5 bytes). The new packet, 5 bytes longer, is built in out (MAX_PACKET_SIZE bytes)
 * with the checksums left to the caller. Returns its length, or 0 when the data is not one whole
 * handshake record, the cut is not inside it, or the packet would not fit in an Ethernet frame.
 */
UINT tls_record_split(char *out, const char *packet, UINT packetLen, UINT data_off,
                      UINT data_len, int packet_v4, unsigned int cut);

#endif
