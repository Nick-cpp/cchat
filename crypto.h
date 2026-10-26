#ifndef CCHAT_CRYPTO_H
#define CCHAT_CRYPTO_H

/*
 * Message encryption for cchat.
 *
 * The key can be set at runtime with cchat_set_key().  If
 * CHAT_ENCRYPTION_KEY is defined before including this header, it is used as
 * the initial key; callers may override it with cchat_set_key().
 *
 * This protects message contents from casual interception.  It is not a
 * replacement for a proper key-exchange protocol.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define CHAT_KEY_MAX 256

#ifdef CHAT_ENCRYPTION_KEY
static char cchat_key[CHAT_KEY_MAX + 1] = CHAT_ENCRYPTION_KEY;
static size_t cchat_key_len = sizeof(CHAT_ENCRYPTION_KEY) - 1;
#else
static char cchat_key[CHAT_KEY_MAX + 1];
static size_t cchat_key_len = 0;
#endif

static inline int cchat_set_key(const char *key) {
    if (key == NULL) {
        cchat_key_len = 0;
        return -1;
    }

    size_t len = strlen(key);
    if (len == 0 || len > CHAT_KEY_MAX) {
        cchat_key_len = 0;
        return -1;
    }

    memset(cchat_key, 0, sizeof(cchat_key));
    memcpy(cchat_key, key, len);
    cchat_key[len] = '\0';
    cchat_key_len = len;
    return 0;
}

#define CHAT_CRYPTO_NONCE_LEN 12
#define CHAT_CRYPTO_TAG_LEN 16
#define CHAT_CRYPTO_OVERHEAD (CHAT_CRYPTO_NONCE_LEN + CHAT_CRYPTO_TAG_LEN)
#define CHAT_MAX_FRAME 4096

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/* ------------------------------ SHA-256 ------------------------------- */

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} cchat_sha256_ctx;

static const uint32_t cchat_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define CCHAT_ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CCHAT_CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define CCHAT_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define CCHAT_EP0(x) (CCHAT_ROTR(x, 2) ^ CCHAT_ROTR(x, 13) ^ CCHAT_ROTR(x, 22))
#define CCHAT_EP1(x) (CCHAT_ROTR(x, 6) ^ CCHAT_ROTR(x, 11) ^ CCHAT_ROTR(x, 25))
#define CCHAT_SIG0(x) (CCHAT_ROTR(x, 7) ^ CCHAT_ROTR(x, 18) ^ ((x) >> 3))
#define CCHAT_SIG1(x) (CCHAT_ROTR(x, 17) ^ CCHAT_ROTR(x, 19) ^ ((x) >> 10))

static void cchat_sha256_transform(cchat_sha256_ctx *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) |
               ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) |
               (uint32_t)data[j + 3];
    }
    for (; i < 64; ++i) {
        m[i] = CCHAT_SIG1(m[i - 2]) + m[i - 7] + CCHAT_SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + CCHAT_EP1(e) + CCHAT_CH(e, f, g) + cchat_sha256_k[i] + m[i];
        t2 = CCHAT_EP0(a) + CCHAT_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void cchat_sha256_init(cchat_sha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void cchat_sha256_update(cchat_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            cchat_sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void cchat_sha256_final(cchat_sha256_ctx *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        cchat_sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    ctx->data[63] = (uint8_t)(ctx->bitlen);
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    cchat_sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (uint8_t)(ctx->state[0] >> (24 - i * 8));
        hash[i + 4]  = (uint8_t)(ctx->state[1] >> (24 - i * 8));
        hash[i + 8]  = (uint8_t)(ctx->state[2] >> (24 - i * 8));
        hash[i + 12] = (uint8_t)(ctx->state[3] >> (24 - i * 8));
        hash[i + 16] = (uint8_t)(ctx->state[4] >> (24 - i * 8));
        hash[i + 20] = (uint8_t)(ctx->state[5] >> (24 - i * 8));
        hash[i + 24] = (uint8_t)(ctx->state[6] >> (24 - i * 8));
        hash[i + 28] = (uint8_t)(ctx->state[7] >> (24 - i * 8));
    }
}

static void cchat_sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
    cchat_sha256_ctx ctx;
    cchat_sha256_init(&ctx);
    cchat_sha256_update(&ctx, data, len);
    cchat_sha256_final(&ctx, hash);
}

static void cchat_hmac_sha256(const uint8_t *key, size_t key_len,
                              const uint8_t *data, size_t data_len,
                              uint8_t out[32]) {
    uint8_t k[64];
    uint8_t ipad[64];
    uint8_t opad[64];
    uint8_t inner[32];
    cchat_sha256_ctx ctx;

    memset(k, 0, sizeof(k));
    if (key_len > sizeof(k)) {
        cchat_sha256(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (size_t i = 0; i < sizeof(k); ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    cchat_sha256_init(&ctx);
    cchat_sha256_update(&ctx, ipad, sizeof(ipad));
    cchat_sha256_update(&ctx, data, data_len);
    cchat_sha256_final(&ctx, inner);

    cchat_sha256_init(&ctx);
    cchat_sha256_update(&ctx, opad, sizeof(opad));
    cchat_sha256_update(&ctx, inner, sizeof(inner));
    cchat_sha256_final(&ctx, out);
}

/* ------------------------------ ChaCha20 ------------------------------ */

static uint32_t cchat_load32_le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void cchat_store32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t cchat_rotl32(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

#define CCHAT_QR(a, b, c, d)                     \
    do {                                         \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = cchat_rotl32(x[d], 16); \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = cchat_rotl32(x[b], 12); \
        x[a] += x[b]; x[d] ^= x[a]; x[d] = cchat_rotl32(x[d], 8);  \
        x[c] += x[d]; x[b] ^= x[c]; x[b] = cchat_rotl32(x[b], 7);  \
    } while (0)

static void cchat_chacha20_block(const uint8_t key[32], const uint8_t nonce[12],
                                 uint32_t counter, uint8_t out[64]) {
    uint32_t state[16];
    uint32_t x[16];

    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = cchat_load32_le(key + i * 4);
    }
    state[12] = counter;
    state[13] = cchat_load32_le(nonce);
    state[14] = cchat_load32_le(nonce + 4);
    state[15] = cchat_load32_le(nonce + 8);

    memcpy(x, state, sizeof(x));

    for (int i = 0; i < 10; ++i) {
        CCHAT_QR(0, 4, 8, 12);
        CCHAT_QR(1, 5, 9, 13);
        CCHAT_QR(2, 6, 10, 14);
        CCHAT_QR(3, 7, 11, 15);
        CCHAT_QR(0, 5, 10, 15);
        CCHAT_QR(1, 6, 11, 12);
        CCHAT_QR(2, 7, 8, 13);
        CCHAT_QR(3, 4, 9, 14);
    }

    for (int i = 0; i < 16; ++i) {
        cchat_store32_le(out + i * 4, x[i] + state[i]);
    }
}

static void cchat_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                               const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t block[64];
    uint32_t counter = 0;

    for (size_t offset = 0; offset < len; offset += 64) {
        size_t chunk = len - offset;
        if (chunk > sizeof(block)) chunk = sizeof(block);

        cchat_chacha20_block(key, nonce, counter++, block);
        for (size_t i = 0; i < chunk; ++i) {
            out[offset + i] = in[offset + i] ^ block[i];
        }
    }
}

/* ---------------------------- Encryption ------------------------------ */

static int cchat_random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    size_t offset = 0;
    while (offset < len) {
        ssize_t n = read(fd, buf + offset, len - offset);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)n;
    }

    close(fd);
    return 0;
}

static void cchat_derive_key(const char *label, uint8_t out[32]) {
    uint8_t master[32];
    cchat_sha256_ctx ctx;

    cchat_sha256((const uint8_t *)cchat_key, cchat_key_len, master);

    cchat_sha256_init(&ctx);
    cchat_sha256_update(&ctx, (const uint8_t *)label, strlen(label));
    cchat_sha256_update(&ctx, master, sizeof(master));
    cchat_sha256_final(&ctx, out);

    memset(master, 0, sizeof(master));
}

static int cchat_constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

/*
 * Wire format produced here:
 *   nonce (12 bytes) || ChaCha20 ciphertext || HMAC-SHA256 tag (16 bytes)
 */
static int cchat_encrypt(const void *plain, size_t plain_len,
                         uint8_t *out, size_t out_cap, size_t *out_len) {
    if (cchat_key_len == 0) return -1;

    if (plain_len > CHAT_MAX_FRAME ||
        out_cap < plain_len + CHAT_CRYPTO_OVERHEAD) {
        return -1;
    }

    uint8_t enc_key[32];
    uint8_t mac_key[32];
    uint8_t *nonce = out;
    uint8_t *cipher = out + CHAT_CRYPTO_NONCE_LEN;
    uint8_t *tag = cipher + plain_len;

    if (cchat_random_bytes(nonce, CHAT_CRYPTO_NONCE_LEN) != 0) return -1;

    cchat_derive_key("cchat message encryption", enc_key);
    cchat_derive_key("cchat message authentication", mac_key);

    cchat_chacha20_xor(enc_key, nonce, (const uint8_t *)plain, plain_len, cipher);
    cchat_hmac_sha256(mac_key, sizeof(mac_key), out,
                      CHAT_CRYPTO_NONCE_LEN + plain_len, tag);

    memset(enc_key, 0, sizeof(enc_key));
    memset(mac_key, 0, sizeof(mac_key));

    *out_len = plain_len + CHAT_CRYPTO_OVERHEAD;
    return 0;
}

static int cchat_decrypt(const uint8_t *in, size_t in_len,
                         void *plain, size_t plain_cap, size_t *plain_len) {
    if (cchat_key_len == 0) return -1;

    if (in_len < CHAT_CRYPTO_OVERHEAD) return -1;

    size_t cipher_len = in_len - CHAT_CRYPTO_OVERHEAD;
    if (cipher_len > plain_cap) return -1;

    const uint8_t *nonce = in;
    const uint8_t *cipher = in + CHAT_CRYPTO_NONCE_LEN;
    const uint8_t *tag = cipher + cipher_len;

    uint8_t enc_key[32];
    uint8_t mac_key[32];
    uint8_t expected[32];

    cchat_derive_key("cchat message encryption", enc_key);
    cchat_derive_key("cchat message authentication", mac_key);

    cchat_hmac_sha256(mac_key, sizeof(mac_key), in,
                      CHAT_CRYPTO_NONCE_LEN + cipher_len, expected);

    int authentic = cchat_constant_time_equal(expected, tag, CHAT_CRYPTO_TAG_LEN);
    if (authentic) {
        cchat_chacha20_xor(enc_key, nonce, cipher, cipher_len, (uint8_t *)plain);
    }

    memset(enc_key, 0, sizeof(enc_key));
    memset(mac_key, 0, sizeof(mac_key));
    memset(expected, 0, sizeof(expected));

    if (!authentic) return -1;

    *plain_len = cipher_len;
    return 0;
}

/* ------------------------------ Base64 -------------------------------- */

static const char cchat_b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int cchat_b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Encodes in_len bytes into out (NUL terminated).  Returns the number of
   characters written, or -1 when out_cap is too small. */
static int cchat_b64_encode(const uint8_t *in, size_t in_len,
                            char *out, size_t out_cap) {
    size_t need = 4 * ((in_len + 2) / 3);
    if (out_cap < need + 1) return -1;

    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len) v |= (uint32_t)in[i + 2];

        out[o++] = cchat_b64_alphabet[(v >> 18) & 63];
        out[o++] = cchat_b64_alphabet[(v >> 12) & 63];
        out[o++] = (i + 1 < in_len) ? cchat_b64_alphabet[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < in_len) ? cchat_b64_alphabet[v & 63] : '=';
    }
    out[o] = '\0';
    return (int)o;
}

/* Decodes base64 text.  Whitespace is ignored and padding is optional.
   Returns 0 on success, -1 on malformed input or if out_cap is too small. */
static int cchat_b64_decode(const char *in, size_t in_len,
                            uint8_t *out, size_t out_cap, size_t *out_len) {
    int vals[4];
    int n = 0;
    int pad = 0;
    size_t o = 0;

    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;

        if (c == '=') {
            if (n < 2) return -1;
            vals[n++] = 0;
            pad++;
        } else {
            int v = cchat_b64_value(c);
            if (v < 0) return -1;
            vals[n++] = v;
        }

        if (n == 4) {
            if (pad > 2) return -1;
            uint32_t v = ((uint32_t)vals[0] << 18) |
                         ((uint32_t)vals[1] << 12) |
                         ((uint32_t)vals[2] << 6) |
                         (uint32_t)vals[3];
            size_t bytes = 3 - (size_t)pad;
            if (o + bytes > out_cap) return -1;
            out[o++] = (uint8_t)(v >> 16);
            if (pad < 2) out[o++] = (uint8_t)(v >> 8);
            if (pad < 1) out[o++] = (uint8_t)v;
            n = 0;
            pad = 0;
        }
    }

    if (n != 0) return -1;
    *out_len = o;
    return 0;
}

/* ------------------------- Framed socket I/O -------------------------- */

static int cchat_send_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t offset = 0;

    while (offset < len) {
        ssize_t n = send(fd, p + offset, len - offset, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1;
        offset += (size_t)n;
    }
    return 1;
}

static int cchat_recv_all(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t offset = 0;

    while (offset < len) {
        ssize_t n = recv(fd, p + offset, len - offset, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return (offset == 0) ? 0 : -1;
        offset += (size_t)n;
    }
    return 1;
}

/* Sends one encrypted, length-prefixed message. */
static int cchat_send_encrypted(int fd, const void *data, size_t len) {
    uint8_t packet[CHAT_CRYPTO_NONCE_LEN + CHAT_MAX_FRAME + CHAT_CRYPTO_TAG_LEN];
    size_t packet_len;

    if (cchat_encrypt(data, len, packet, sizeof(packet), &packet_len) != 0) {
        return -1;
    }

    uint32_t net_len = htonl((uint32_t)packet_len);
    if (cchat_send_all(fd, &net_len, sizeof(net_len)) != 1) return -1;
    if (cchat_send_all(fd, packet, packet_len) != 1) return -1;
    return 1;
}

/*
 * Receives one encrypted, length-prefixed message.
 * Returns 1 on success, 0 when the peer closed the connection, -1 on error.
 */
static int cchat_recv_encrypted(int fd, void *out, size_t out_cap, size_t *out_len) {
    uint8_t packet[CHAT_CRYPTO_NONCE_LEN + CHAT_MAX_FRAME + CHAT_CRYPTO_TAG_LEN];
    uint32_t net_len;

    int rc = cchat_recv_all(fd, &net_len, sizeof(net_len));
    if (rc <= 0) return rc;

    uint32_t packet_len = ntohl(net_len);
    if (packet_len < CHAT_CRYPTO_OVERHEAD ||
        packet_len > sizeof(packet)) {
        return -1;
    }

    rc = cchat_recv_all(fd, packet, packet_len);
    if (rc <= 0) return rc;

    if (cchat_decrypt(packet, packet_len, out, out_cap, out_len) != 0) {
        return -1;
    }
    return 1;
}

#endif /* CCHAT_CRYPTO_H */
