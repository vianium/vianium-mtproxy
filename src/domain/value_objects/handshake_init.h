// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstdint>
#include "mt_proxy_secret.h"

namespace vianium { namespace mtproxy {

// =============================================================================
// HandshakeInit — the 64-byte first packet a client sends to an MTProxy.
// =============================================================================
//
// Layout (all little-endian):
//
//     bytes  0 ..  7   random padding with constraints
//     bytes  8 .. 55   random body (used to derive AES-CTR keys + IVs)
//     bytes 56 .. 59   protocol identifier (kProtocolAbridged etc.)
//     bytes 60 .. 61   dc_id (int16; positive = main, negative = media-only)
//     bytes 62 .. 63   random padding
//
// Constraints on byte 0..7:
//     first byte    : not 0xEF (legacy abridged sentinel)
//     first 4 bytes : not 0x44414548 (HEAD), 0x54534F50 (POST),
//                     0x20544547 (GET ), 0x4954504F (OPTI),
//                     0xDDDDDDDD, 0xEEEEEEEE   — these would look like
//                     other protocols' first bytes and trigger DPI.
//     bytes 4..7    : not 0x00000000 (avoid empty key block).
//
// After construction, bytes 56..63 are themselves encrypted using the
// derived AES-CTR encryption key/IV — so what travels on the wire is
// the *encrypted* tail, not the literal protocol marker.
//
// Source: https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation
// =============================================================================

enum : uint32_t
{
    kProtocolAbridged           = 0xEFEFEFEFu,
    kProtocolIntermediate       = 0xEEEEEEEEu,
    kProtocolPaddedIntermediate = 0xDDDDDDDDu
};

struct ObfuscatedKeys
{
    uint8_t encrypt_key[32];
    uint8_t encrypt_iv [16];
    uint8_t decrypt_key[32];
    uint8_t decrypt_iv [16];
};

struct HandshakeOutput
{
    uint8_t        init_packet[64];   // bytes that go on the wire
    ObfuscatedKeys keys;
};

// =============================================================================
// HandshakeInit
// =============================================================================
//
// Pure builder. No I/O. Given a secret, a dc_id, a 58-byte randomness
// blob, and a protocol selector, it produces:
//
//     * the 64-byte init packet (bytes 56..63 already encrypted), and
//     * the four AES-CTR materials (enc_key, enc_iv, dec_key, dec_iv).
//
// The caller is responsible for sourcing 58 cryptographically-strong
// random bytes (e.g. via Windows.Security.Cryptography.CryptographicBuffer
// in the WinRT layer) and discarding any sample that fails
// IsValidRandomness().
// =============================================================================

class HandshakeInit
{
public:
    // Returns true if the 58-byte randomness draw passes the wire-format
    // constraints described above. Callers should re-draw on false.
    static VIANIUM_MTPROXY_API bool IsValidRandomness(const uint8_t randomness[58]);

    // Build the init packet + key material. Returns false only if the
    // randomness fails the constraints (paranoid double-check; callers
    // should pre-filter with IsValidRandomness()).
    //
    // protocol_marker  — one of kProtocolAbridged / kProtocolIntermediate
    //                    / kProtocolPaddedIntermediate.
    // dc_id            — Telegram data-centre id (1..5 for production,
    //                    -1..-5 for media-only sockets, +10000-shifted
    //                    for test DCs).
    static VIANIUM_MTPROXY_API bool Build(const MtProxySecret& secret,
                      uint32_t              protocol_marker,
                      int16_t               dc_id,
                      const uint8_t         randomness[58],
                      HandshakeOutput*      out);
};

}}  // namespace vianium::mtproxy
