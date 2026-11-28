/*
 * Sending a packet in pieces: native fragments and the cuts of --split-pos.
 */

#include <string.h>
#include "adiosdpi.h"
#include "sendsplit.h"
#include "splitpos.h"

/** Fragment and queue the packet.
 *
 * This function cuts off the end of the packet (step=0) or
 * the beginning of the packet (step=1) with fragment_size bytes.
 */
void send_native_fragment(HANDLE w_filter, WINDIVERT_ADDRESS addr,
                          char *packet, UINT packetLen, PVOID packet_data,
                          UINT packet_dataLen, int packet_v4, int packet_v6,
                          PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr,
                          PWINDIVERT_TCPHDR ppTcpHdr,
                          unsigned int fragment_size, int step) {
    char packet_bak[MAX_PACKET_SIZE];
    memcpy(packet_bak, packet, packetLen);
    UINT orig_packetLen = packetLen;

    if (fragment_size >= packet_dataLen) {
        if (step == 1)
            fragment_size = 0;
        else
            return;
    }

    if (step == 0) {
        if (packet_v4)
            ppIpHdr->Length = htons(
                ntohs(ppIpHdr->Length) -
                packet_dataLen + fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->Length = htons(
                ntohs(ppIpV6Hdr->Length) -
                packet_dataLen + fragment_size
            );
        //printf("step0 (%d:%d), pp:%d, was:%d, now:%d\n",
        //                packet_v4, packet_v6, ntohs(ppIpHdr->Length),
        //                packetLen, packetLen - packet_dataLen + fragment_size);
        packetLen = packetLen - packet_dataLen + fragment_size;
    }

    else if (step == 1) {
        if (packet_v4)
            ppIpHdr->Length = htons(
                ntohs(ppIpHdr->Length) - fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->Length = htons(
                ntohs(ppIpV6Hdr->Length) - fragment_size
            );
        //printf("step1 (%d:%d), pp:%d, was:%d, now:%d\n", packet_v4, packet_v6, ntohs(ppIpHdr->Length),
        //                packetLen, packetLen - fragment_size);
        memmove(packet_data,
                (char*)packet_data + fragment_size,
                packet_dataLen - fragment_size);
        packetLen -= fragment_size;

        ppTcpHdr->SeqNum = htonl(ntohl(ppTcpHdr->SeqNum) + fragment_size);
    }

    addr.IPChecksum = 0;
    addr.TCPChecksum = 0;

    WinDivertHelperCalcChecksums(
        packet, packetLen, &addr, 0
    );
    queue_tx(w_filter, packet, packetLen, &addr);
    memcpy(packet, packet_bak, orig_packetLen);
    //printf("Sent native fragment of %d size (step%d)\n", packetLen, step);
}

/*
 * Sends the data of a packet in count + 1 pieces, cut at cuts[0..count-1]: in order, or the last
 * piece first. Every piece keeps the headers; its length and sequence number are made to fit.
 *
 * The first piece can start seqovl bytes early: its sequence number is lowered by seqovl and the
 * bytes in front of the data are zeros. The server has those sequence numbers already, throws the
 * bytes away and keeps the data; a DPI box that does not do the same reads a different stream.
 *
 * The pieces are built in a buffer of their own: the packet may sit in the middle of a batch, and
 * a piece with extra bytes must not run over the next packet.
 */
void send_split(HANDLE w_filter, WINDIVERT_ADDRESS addr,
                char *packet, UINT packetLen, PVOID packet_data, UINT packet_dataLen,
                int packet_v4, int packet_v6,
                PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr, PWINDIVERT_TCPHDR ppTcpHdr,
                const unsigned int *cuts, int count, unsigned int seqovl, int reverse) {
    char work[MAX_PACKET_SIZE];
    unsigned int bounds[SPLIT_MAX + 2];
    UINT data_off = (UINT)((char *)packet_data - packet), tcp_off = (UINT)((char *)ppTcpHdr - packet);
    UINT ip_length = ntohs(packet_v4 ? ppIpHdr->Length : ppIpV6Hdr->Length);
    int k;

    bounds[0] = 0;
    memcpy(bounds + 1, cuts, (size_t)count * sizeof(*cuts));
    bounds[count + 1] = packet_dataLen;
    for (k = 0; k <= count; k++) {
        int piece = reverse ? count - k : k;
        unsigned int from = bounds[piece], len = bounds[piece + 1] - from;
        unsigned int pad = (from == 0 && data_off + seqovl + len <= MAX_PACKET_SIZE) ? seqovl : 0;
        UINT piece_len = data_off + pad + len;
        PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(work + tcp_off);

        (void)packetLen;
        memcpy(work, packet, data_off);
        memset(work + data_off, 0, pad);
        memcpy(work + data_off + pad, (char *)packet_data + from, len);
        if (packet_v4)
            ((PWINDIVERT_IPHDR)work)->Length = htons((UINT16)(ip_length - packet_dataLen + pad + len));
        else if (packet_v6)
            ((PWINDIVERT_IPV6HDR)work)->Length = htons((UINT16)(ip_length - packet_dataLen + pad + len));
        tcp->SeqNum = htonl(ntohl(ppTcpHdr->SeqNum) + from - pad);
        addr.IPChecksum = 0;
        addr.TCPChecksum = 0;
        WinDivertHelperCalcChecksums(work, piece_len, &addr, 0);
        queue_tx(w_filter, work, piece_len, &addr);
    }
}
