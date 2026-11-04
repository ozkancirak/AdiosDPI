#ifndef _QUIC_H
#define _QUIC_H
#include <stddef.h>

/*
 * Is this UDP payload the first packet of a QUIC (version 1) connection, a client Initial?
 * Only the header is looked at: the rest is encrypted.
 */
int quic_is_initial(const unsigned char *payload, unsigned int len);

/*
 * Builds a client Initial packet and protects it the way RFC 9001 says (section 5 and
 * appendix A). The keys come from the destination connection ID alone, so anyone on the path
 * can read the packet, a DPI box included.
 *
 * frames is the unprotected payload (CRYPTO and PADDING frames), pn the packet number.
 * Returns the size of the packet written to out, or 0 if it does not fit or the system
 * crypto fails.
 */
size_t quic_protect_initial(const unsigned char *dcid, size_t dcid_len,
                            const unsigned char *scid, size_t scid_len,
                            unsigned long pn, const unsigned char *frames, size_t frames_len,
                            unsigned char *out, size_t out_size);

/*
 * Builds a whole client Initial of 1250 bytes with a TLS ClientHello for the server name sni,
 * random connection IDs and keys. Returns its size, or 0 on failure.
 */
size_t quic_make_fake_initial(const char *sni, unsigned char *out, size_t out_size);

#endif
