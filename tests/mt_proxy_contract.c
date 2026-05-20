/*
 * SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>
 *
 * vianium-mtproxy contract test.
 *
 * Mirrors the per-context contract-test pattern established by
 * vianium-browser (see Core/Vianium.Core.Css/tests/css_contract.c
 * et al.). It exercises the wire-level invariants of the MTProxy
 * obfuscation layer using only the public C surface and a small
 * deterministic test vector.
 *
 * The vector cannot be the official Telegram-issued one (their server
 * does not publish them), so we synthesise a deterministic input and
 * round-trip it: encode + decode using the same key material and
 * assert the plaintext returns identical to the input.
 *
 * Build (Developer Command Prompt for VS2015):
 *
 *     cl /TC /I..\include mt_proxy_contract.c \
 *        /link /OUT:mt_proxy_contract.exe \
 *              ..\bin\Debug\Vianium.MtProxy.lib
 *
 * Run:
 *     mt_proxy_contract.exe
 *
 * Exit code 0 = pass, non-zero = fail (with stdout diagnostics).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------- */
/* Forward declarations of the C-callable bridge.                       */
/*                                                                      */
/* The full WinRT projection is in src\api\v1\MtProxyApi.h, but for the */
/* contract test we hand-extern the two C-callable functions that the   */
/* infrastructure layer exports for in-process tests.                   */
/* -------------------------------------------------------------------- */

extern void vianium_mtproxy_aes_ctr_xor(
    const unsigned char key[32],
    unsigned char       iv [16],
    unsigned char*      data,
    size_t              length);

extern int vianium_mtproxy_build_handshake(
    const unsigned char secret    [16],
    unsigned int        protocol_marker,
    short               dc_id,
    const unsigned char randomness[58],
    unsigned char       init_packet[64],
    unsigned char       enc_key   [32],
    unsigned char       enc_iv    [16],
    unsigned char       dec_key   [32],
    unsigned char       dec_iv    [16]);

/* -------------------------------------------------------------------- */
/* Test vector — deterministic; the values themselves don't matter.    */
/* What we assert is the round-trip property: encrypt(decrypt(x)) == x. */
/* -------------------------------------------------------------------- */

static const unsigned char kSecret[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

/* 58 bytes of "randomness" with byte 0 != 0xEF and first word not in
 * the forbidden table. Bytes 4..7 are non-zero. */
static const unsigned char kRandomness[58] = {
    0x12, 0x34, 0x56, 0x78,  0xAB, 0xCD, 0xEF, 0x01,
    0x02, 0x03, 0x04, 0x05,  0x06, 0x07, 0x08, 0x09,
    0x0A, 0x0B, 0x0C, 0x0D,  0x0E, 0x0F, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15,  0x16, 0x17, 0x18, 0x19,
    0x1A, 0x1B, 0x1C, 0x1D,  0x1E, 0x1F, 0x20, 0x21,
    0x22, 0x23, 0x24, 0x25,  0x26, 0x27, 0x28, 0x29,
    0x2A, 0x2B, 0x2C, 0x2D,  0x2E, 0x2F, 0x30, 0x31,
    0x32, 0x33
};

#define EXPECT(cond, message)                                    \
    do {                                                          \
        if (!(cond)) {                                            \
            fprintf(stderr, "[mt_proxy_contract] FAIL: %s\n",     \
                    (message));                                   \
            return 1;                                             \
        }                                                         \
    } while (0)

int main(void)
{
    unsigned char init[64];
    unsigned char ek[32], ei[16], dk[32], di[16];

    int ok = vianium_mtproxy_build_handshake(
        kSecret, 0xEEEEEEEEu /* Intermediate */, 2 /* dc_id */,
        kRandomness, init, ek, ei, dk, di);
    EXPECT(ok != 0, "handshake build returned false on a valid vector");

    /* Bytes 8..55 of init must be the literal prekey + IV. The server
     * reads them directly to derive its own ciphers. */
    EXPECT(memcmp(init + 8, kRandomness + 8, 48) == 0,
           "init bytes 8..55 must mirror the randomness (prekey + IV)");

    /* Bytes 0..7 must NOT be the literal randomness — they should be
     * AES-CTR encrypted on the wire to defeat DPI fingerprinting.
     * Verified against the reference servers 9seconds/mtg and
     * alexbers/mtprotoproxy. */
    EXPECT(memcmp(init, kRandomness, 8) != 0,
           "init bytes 0..7 must be encrypted on the wire");

    /* Bytes 56..59 must NOT be the literal protocol marker. */
    {
        unsigned int wire_marker =
            (unsigned int)init[56]        |
            ((unsigned int)init[57] << 8) |
            ((unsigned int)init[58] << 16)|
            ((unsigned int)init[59] << 24);
        EXPECT(wire_marker != 0xEEEEEEEEu,
               "init bytes 56..59 must be encrypted on the wire");
    }

    /* AES-CTR round-trip property — encrypt(decrypt(x)) == x. */
    unsigned char plaintext[256];
    for (size_t i = 0; i < sizeof(plaintext); ++i)
        plaintext[i] = (unsigned char)(i & 0xFF);

    unsigned char ciphertext[256];
    memcpy(ciphertext, plaintext, sizeof(plaintext));

    unsigned char enc_iv[16];
    memcpy(enc_iv, ei, 16);
    vianium_mtproxy_aes_ctr_xor(ek, enc_iv, ciphertext, sizeof(ciphertext));

    EXPECT(memcmp(ciphertext, plaintext, sizeof(plaintext)) != 0,
           "ciphertext must differ from plaintext");

    unsigned char recovered[256];
    memcpy(recovered, ciphertext, sizeof(ciphertext));

    /* Reset IV to the same starting point — the receiver does the
     * same on its decrypt counterpart. */
    unsigned char enc_iv2[16];
    memcpy(enc_iv2, ei, 16);
    vianium_mtproxy_aes_ctr_xor(ek, enc_iv2, recovered, sizeof(recovered));

    EXPECT(memcmp(recovered, plaintext, sizeof(plaintext)) == 0,
           "AES-CTR round-trip lost data");

    printf("[mt_proxy_contract] PASS — 2 invariants verified\n");
    return 0;
}
