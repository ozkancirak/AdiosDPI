/*
 * QUIC Initial packets: recognizing them and building protected ones (RFC 9001).
 * Windows' own crypto (CNG) does the hashing and the AES, so there is nothing to link but bcrypt.
 */

#include <windows.h>
#include <bcrypt.h>
#include <string.h>
#include "quic.h"

#define FAKE_DATAGRAM_SIZE 1250     /* a client Initial must be at least 1200 */

/* The salt of QUIC version 1, from RFC 9001 section 5.2. */
static const unsigned char initial_salt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

int quic_is_initial(const unsigned char *payload, unsigned int len) {
    /* long header (0x80), fixed bit (0x40), packet type Initial (00), then the version */
    return len >= 5 && (payload[0] & 0xF0) == 0xC0 &&
           payload[1] == 0 && payload[2] == 0 && payload[3] == 0 && payload[4] == 1;
}

static int hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *data, size_t data_len,
                       unsigned char out[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    int ok = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) == 0) {
        if (BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0) == 0) {
            ok = BCryptHashData(hash, (PUCHAR)data, (ULONG)data_len, 0) == 0 &&
                 BCryptFinishHash(hash, out, 32, 0) == 0;
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return ok;
}

/* HKDF-Expand-Label of TLS 1.3 with an empty context and at most 32 bytes of output (one HMAC block). */
static int expand_label(const unsigned char secret[32], const char *label, unsigned char *out, size_t out_len) {
    unsigned char info[64], block[32];
    size_t label_len = strlen(label), n = 0;

    info[n++] = 0;
    info[n++] = (unsigned char)out_len;
    info[n++] = (unsigned char)(6 + label_len);
    memcpy(info + n, "tls13 ", 6);
    n += 6;
    memcpy(info + n, label, label_len);
    n += label_len;
    info[n++] = 0;                      /* empty context */
    info[n++] = 1;                      /* first and only block of HKDF-Expand */
    if (!hmac_sha256(secret, 32, info, n, block))
        return 0;
    memcpy(out, block, out_len);
    return 1;
}

/* The client's packet protection keys for a destination connection ID. */
static int derive_keys(const unsigned char *dcid, size_t dcid_len,
                       unsigned char key[16], unsigned char iv[12], unsigned char hp[16]) {
    unsigned char initial[32], client[32];

    return hmac_sha256(initial_salt, sizeof(initial_salt), dcid, dcid_len, initial) &&
           expand_label(initial, "client in", client, 32) &&
           expand_label(client, "quic key", key, 16) &&
           expand_label(client, "quic iv", iv, 12) &&
           expand_label(client, "quic hp", hp, 16);
}

/* AES-128-GCM of the payload; the 16 byte tag goes right after it. */
static int aead_seal(const unsigned char key[16], const unsigned char iv[12],
                     const unsigned char *aad, size_t aad_len,
                     const unsigned char *in, size_t len, unsigned char *out) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE handle = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    ULONG done = 0;
    int ok = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return 0;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) == 0 &&
        BCryptGenerateSymmetricKey(alg, &handle, NULL, 0, (PUCHAR)key, 16, 0) == 0) {
        BCRYPT_INIT_AUTH_MODE_INFO(info);
        info.pbNonce = (PUCHAR)iv;
        info.cbNonce = 12;
        info.pbAuthData = (PUCHAR)aad;
        info.cbAuthData = (ULONG)aad_len;
        info.pbTag = out + len;
        info.cbTag = 16;
        ok = BCryptEncrypt(handle, (PUCHAR)in, (ULONG)len, &info, NULL, 0, out, (ULONG)len, &done, 0) == 0;
        BCryptDestroyKey(handle);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

/* The 5 byte header protection mask: AES-ECB of a 16 byte sample of the protected payload. */
static int header_mask(const unsigned char hp[16], const unsigned char *sample, unsigned char mask[16]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE handle = NULL;
    ULONG done = 0;
    int ok = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0)
        return 0;
    if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0) == 0 &&
        BCryptGenerateSymmetricKey(alg, &handle, NULL, 0, (PUCHAR)hp, 16, 0) == 0) {
        ok = BCryptEncrypt(handle, (PUCHAR)sample, 16, NULL, NULL, 0, mask, 16, &done, 0) == 0;
        BCryptDestroyKey(handle);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

size_t quic_protect_initial(const unsigned char *dcid, size_t dcid_len,
                            const unsigned char *scid, size_t scid_len,
                            unsigned long pn, const unsigned char *frames, size_t frames_len,
                            unsigned char *out, size_t out_size) {
    unsigned char key[16], iv[12], hp[16], mask[16], nonce[12];
    size_t n = 0, pn_off, total, length;
    int i;

    /* the length field is a two byte varint and the sample needs 4 bytes of packet number plus 16 of payload */
    length = 4 + frames_len + 16;
    if (dcid_len > 20 || scid_len > 20 || length > 0x3FFF)
        return 0;
    total = 1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + 2 + length;
    if (total > out_size || !derive_keys(dcid, dcid_len, key, iv, hp))
        return 0;

    out[n++] = 0xC3;                    /* long header, Initial, 4 byte packet number */
    out[n++] = 0; out[n++] = 0; out[n++] = 0; out[n++] = 1;     /* version 1 */
    out[n++] = (unsigned char)dcid_len;
    memcpy(out + n, dcid, dcid_len);
    n += dcid_len;
    out[n++] = (unsigned char)scid_len;
    if (scid_len)
        memcpy(out + n, scid, scid_len);
    n += scid_len;
    out[n++] = 0;                       /* no token */
    out[n++] = (unsigned char)(0x40 | (length >> 8));
    out[n++] = (unsigned char)length;
    pn_off = n;
    for (i = 3; i >= 0; i--)
        out[n++] = (unsigned char)(pn >> (8 * i));

    memcpy(nonce, iv, sizeof(nonce));
    for (i = 0; i < 4; i++)
        nonce[11 - i] ^= (unsigned char)(pn >> (8 * i));
    if (!aead_seal(key, nonce, out, n, frames, frames_len, out + n))
        return 0;
    if (!header_mask(hp, out + pn_off + 4, mask))
        return 0;
    out[0] ^= mask[0] & 0x0F;
    for (i = 0; i < 4; i++)
        out[pn_off + (size_t)i] ^= mask[1 + i];
    return total;
}

static size_t put_u16(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)(v >> 8);
    p[1] = (unsigned char)v;
    return 2;
}

/* A small TLS 1.3 ClientHello for QUIC: handshake message only, without the record header. */
static size_t build_client_hello(const char *sni, unsigned char *out, size_t size) {
    static const unsigned char tail[] = {
        0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d,             /* supported groups: x25519 */
        0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33,       /* ALPN: h3 */
        0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04, /* signature algorithms */
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,                   /* supported versions: TLS 1.3 */
    };
    static const unsigned char params[] = {
        0x01, 0x02, 0x67, 0x10,                                     /* max_idle_timeout 30000 */
        0x04, 0x04, 0x80, 0x10, 0x00, 0x00,                         /* initial_max_data 1 MiB */
        0x03, 0x02, 0x45, 0xc0,                                     /* max_udp_payload_size 1472 */
    };
    size_t name_len = strlen(sni), p = 0, ext_len_at, ext_start;
    unsigned char random[32], share[32];

    if (name_len == 0 || name_len > 200 || size < 400)
        return 0;
    if (BCryptGenRandom(NULL, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0 ||
        BCryptGenRandom(NULL, share, sizeof(share), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return 0;

    out[p++] = 0x01;                    /* ClientHello; the 3 byte length comes last */
    p += 3;
    out[p++] = 0x03; out[p++] = 0x03;
    memcpy(out + p, random, sizeof(random));
    p += sizeof(random);
    out[p++] = 0;                       /* no session id */
    p += put_u16(out + p, 6);
    p += put_u16(out + p, 0x1301);
    p += put_u16(out + p, 0x1302);
    p += put_u16(out + p, 0x1303);
    out[p++] = 1; out[p++] = 0;         /* no compression */
    ext_len_at = p;
    p += 2;
    ext_start = p;

    p += put_u16(out + p, 0x0000);      /* server_name */
    p += put_u16(out + p, (unsigned)name_len + 5);
    p += put_u16(out + p, (unsigned)name_len + 3);
    out[p++] = 0;
    p += put_u16(out + p, (unsigned)name_len);
    memcpy(out + p, sni, name_len);
    p += name_len;

    memcpy(out + p, tail, sizeof(tail));
    p += sizeof(tail);

    p += put_u16(out + p, 0x0033);      /* key_share: x25519 */
    p += put_u16(out + p, 38);
    p += put_u16(out + p, 36);
    p += put_u16(out + p, 0x001d);
    p += put_u16(out + p, 32);
    memcpy(out + p, share, sizeof(share));
    p += sizeof(share);

    p += put_u16(out + p, 0x0039);      /* quic_transport_parameters */
    p += put_u16(out + p, sizeof(params));
    memcpy(out + p, params, sizeof(params));
    p += sizeof(params);

    put_u16(out + ext_len_at, (unsigned)(p - ext_start));
    out[1] = (unsigned char)((p - 4) >> 16);
    out[2] = (unsigned char)((p - 4) >> 8);
    out[3] = (unsigned char)(p - 4);
    return p;
}

size_t quic_make_fake_initial(const char *sni, unsigned char *out, size_t out_size) {
    unsigned char hello[512], frames[FAKE_DATAGRAM_SIZE], dcid[8];
    size_t hello_len, frames_len, header_len;

    if (out_size < FAKE_DATAGRAM_SIZE)
        return 0;
    hello_len = build_client_hello(sni, hello, sizeof(hello));
    if (!hello_len || BCryptGenRandom(NULL, dcid, sizeof(dcid), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return 0;

    /* header: flags, version, DCID length and value, no SCID, no token, 2 byte length, 4 byte packet number; then the tag */
    header_len = 1 + 4 + 1 + sizeof(dcid) + 1 + 1 + 2 + 4;
    frames_len = FAKE_DATAGRAM_SIZE - header_len - 16;
    memset(frames, 0, frames_len);      /* what is left over stays PADDING */
    frames[0] = 0x06;                   /* CRYPTO frame at offset 0 */
    frames[1] = 0x00;
    put_u16(frames + 2, 0x4000 | (unsigned)hello_len);
    memcpy(frames + 4, hello, hello_len);
    return quic_protect_initial(dcid, sizeof(dcid), NULL, 0, 0, frames, frames_len, out, out_size);
}
