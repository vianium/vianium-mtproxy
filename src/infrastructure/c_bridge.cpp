// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

// -----------------------------------------------------------------------------
// C bridge for in-process contract tests.
//
// The WinRT projection in src\api\v1\MtProxyApi.{h,cpp} is the public
// API every consumer should use. This bridge exists solely so the
// pure-C contract test in tests\mt_proxy_contract.c can exercise the
// native code without dragging in the C++/CX layer.
//
// Both functions here are dll-exported so they appear in the import
// library and resolve at link time when the test links
// Vianium.MtProxy.lib. They are NOT a stable public API; downstream
// code must not depend on these symbols.
// -----------------------------------------------------------------------------

#include "pch.h"
#include "../domain/value_objects/mt_proxy_secret.h"
#include "../domain/value_objects/handshake_init.h"
#include "../infrastructure/obfuscated_codec.h"

#include <cstddef>
#include <cstdint>

extern "C" {

__declspec(dllexport) void vianium_mtproxy_aes_ctr_xor(
    const unsigned char key[32],
    unsigned char       iv [16],
    unsigned char*      data,
    size_t              length)
{
    vianium::mtproxy::AesCtrXorInPlace(
        reinterpret_cast<const uint8_t*>(key),
        reinterpret_cast<uint8_t*>(iv),
        reinterpret_cast<uint8_t*>(data),
        length);
}

__declspec(dllexport) int vianium_mtproxy_build_handshake(
    const unsigned char secret    [16],
    unsigned int        protocol_marker,
    short               dc_id,
    const unsigned char randomness[58],
    unsigned char       init_packet[64],
    unsigned char       enc_key   [32],
    unsigned char       enc_iv    [16],
    unsigned char       dec_key   [32],
    unsigned char       dec_iv    [16])
{
    vianium::mtproxy::MtProxySecret native_secret =
        vianium::mtproxy::MtProxySecret::FromLegacyBytes(
            reinterpret_cast<const uint8_t*>(secret));

    vianium::mtproxy::HandshakeOutput out;
    bool ok = vianium::mtproxy::HandshakeInit::Build(
        native_secret,
        static_cast<uint32_t>(protocol_marker),
        static_cast<int16_t>(dc_id),
        reinterpret_cast<const uint8_t*>(randomness),
        &out);
    if (!ok) return 0;

    std::memcpy(init_packet, out.init_packet,        64);
    std::memcpy(enc_key,     out.keys.encrypt_key,   32);
    std::memcpy(enc_iv,      out.keys.encrypt_iv,    16);
    std::memcpy(dec_key,     out.keys.decrypt_key,   32);
    std::memcpy(dec_iv,      out.keys.decrypt_iv,    16);
    return 1;
}

}  // extern "C"
