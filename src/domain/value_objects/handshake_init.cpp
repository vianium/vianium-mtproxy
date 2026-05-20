// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "pch.h"
#include "../../domain/value_objects/handshake_init.h"

// SHA-256 lives in vianium-crypto.
#include <vianium/crypto/sha256.h>

#include <cstring>

namespace vianium { namespace mtproxy {

// Forbidden 4-byte prefixes — anything that would make this packet look
// like the first 4 bytes of another protocol or trigger DPI.
static const uint32_t kForbiddenFirstWord[] = {
    0x44414548u,  // "HEAD"
    0x54534F50u,  // "POST"
    0x20544547u,  // "GET "
    0x4954504Fu,  // "OPTI"
    0xDDDDDDDDu,  // padded-intermediate sentinel
    0xEEEEEEEEu,  // intermediate sentinel
    0x02010316u   // first 4 bytes of a real TLS ClientHello (kept off
                  // to avoid colliding with fakeTLS path; harmless guard)
};

static uint32_t LoadLE32(const uint8_t* p)
{
    return  static_cast<uint32_t>(p[0])        |
           (static_cast<uint32_t>(p[1]) << 8)  |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

static void StoreLE32(uint8_t* p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v       & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8 ) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

static void StoreLE16(uint8_t* p, int16_t v)
{
    uint16_t u = static_cast<uint16_t>(v);
    p[0] = static_cast<uint8_t>(u       & 0xFF);
    p[1] = static_cast<uint8_t>((u >> 8) & 0xFF);
}

bool HandshakeInit::IsValidRandomness(const uint8_t r[58])
{
    // The first byte must not be 0xEF — that is the abridged-mode
    // sentinel and would short-circuit obfuscation.
    if (r[0] == 0xEFu) return false;

    // First word check.
    const uint32_t first_word = LoadLE32(r);
    for (size_t i = 0; i < sizeof(kForbiddenFirstWord) / sizeof(uint32_t); ++i)
    {
        if (first_word == kForbiddenFirstWord[i]) return false;
    }

    // Bytes 4..7 must not all be zero (would yield a degenerate AES IV
    // candidate after slicing).
    if (LoadLE32(r + 4) == 0u) return false;

    return true;
}

// -----------------------------------------------------------------------------
// AES-CTR encrypt-in-place using vianium-crypto's AES core.
//
// Used here only for the single 8-byte block that follows the IV
// fragment in the init packet (bytes 56..63). The full stream codec
// lives in infrastructure/obfuscated_codec.{h,cpp} so callers can
// stream-encrypt arbitrary lengths after the handshake completes.
// -----------------------------------------------------------------------------

}}  // namespace vianium::mtproxy

// Forward-declare the codec entry point used here so the handshake
// builder doesn't have to drag in the full codec header.
namespace vianium { namespace mtproxy {
    void AesCtrXorInPlace(const uint8_t key[32],
                          uint8_t       iv [16],
                          uint8_t*      data,
                          size_t        length);
}}

namespace vianium { namespace mtproxy {

bool HandshakeInit::Build(const MtProxySecret& secret,
                          uint32_t              protocol_marker,
                          int16_t               dc_id,
                          const uint8_t         randomness[58],
                          HandshakeOutput*      out)
{
    if (out == nullptr) return false;
    if (!IsValidRandomness(randomness)) return false;

    uint8_t* init = out->init_packet;
    std::memset(init, 0, 64);

    // Layout in order:
    //   bytes 0..7    : randomness[0..7]
    //   bytes 8..55   : randomness[8..55]
    std::memcpy(init,        randomness,        56);

    // bytes 56..59 : protocol marker
    StoreLE32(init + 56, protocol_marker);

    // bytes 60..61 : dc_id
    StoreLE16(init + 60, dc_id);

    // bytes 62..63 : 2 random tail bytes (re-use last 2 of randomness draw)
    init[62] = randomness[56];
    init[63] = randomness[57];

    // ----------- Key derivation ------------------------------------------
    // enc_key = SHA-256(init[8..40]      ++ secret)
    // enc_iv  =          init[40..56]
    //
    // For the decrypt direction, reverse the same 48-byte window:
    //   reversed = reverse(init[8..56])           // 48 bytes
    // dec_key = SHA-256(reversed[0..32]   ++ secret)
    // dec_iv  =          reversed[32..48]
    // ----------------------------------------------------------------------

    const uint8_t* secret_bytes = secret.Bytes();

    // -- enc material --
    {
        uint8_t input[32 + 16];
        std::memcpy(input,        init + 8,      32);
        std::memcpy(input + 32,   secret_bytes,  16);
        vianium::crypto::Sha256::Hash(input, sizeof(input), out->keys.encrypt_key);
        std::memcpy(out->keys.encrypt_iv, init + 40, 16);
    }

    // -- dec material --
    {
        uint8_t reversed[48];
        for (size_t i = 0; i < 48; ++i) reversed[i] = init[8 + 47 - i];

        uint8_t input[32 + 16];
        std::memcpy(input,        reversed,      32);
        std::memcpy(input + 32,   secret_bytes,  16);
        vianium::crypto::Sha256::Hash(input, sizeof(input), out->keys.decrypt_key);
        std::memcpy(out->keys.decrypt_iv, reversed + 32, 16);
    }

    // ----------- Encrypt the wire packet ----------------------------------
    //
    // Per the MTProxy v2 spec and the reference implementations
    // (9seconds/mtg, alexbers/mtprotoproxy):
    //
    //   1. Encrypt the WHOLE 64-byte init packet with the send cipher
    //      starting at counter offset 0.
    //   2. Then OVERWRITE bytes 8..56 with the original plaintext
    //      (those bytes are the prekey + IV material the server reads
    //      directly to derive its own keys).
    //
    // Resulting wire layout:
    //   bytes  0 ..  7  — encrypted random padding (anti-DPI)
    //   bytes  8 .. 55  — plaintext key/IV material (consumed by server)
    //   bytes 56 .. 63  — encrypted protocol marker + dc_id + random tail
    //
    // The server's recv cipher, derived from the same wire bytes 8..56,
    // decrypts the whole 64-byte buffer (bytes 0..7 and 56..63 yield
    // meaningful plaintext; bytes 8..55 decrypt to garbage that the
    // server discards). After that the AES-CTR counter is at offset 64
    // and all subsequent stream data decrypts normally.
    // ----------------------------------------------------------------------

    // Snapshot the prekey + IV before encryption so we can restore them.
    uint8_t prekey_and_iv[48];
    std::memcpy(prekey_and_iv, init + 8, 48);

    uint8_t enc_iv_copy[16];
    std::memcpy(enc_iv_copy, out->keys.encrypt_iv, 16);

    // Encrypt the whole 64-byte init packet in place.
    AesCtrXorInPlace(out->keys.encrypt_key, enc_iv_copy, init, 64);

    // Restore bytes 8..56 to the literal prekey + IV. Bytes 0..7 stay
    // encrypted (the wire form expected by every conforming proxy).
    std::memcpy(init + 8, prekey_and_iv, 48);

    return true;
}

}}  // namespace vianium::mtproxy
