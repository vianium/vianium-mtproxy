// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstdint>
#include <cstddef>
#include "../domain/value_objects/mt_proxy_secret.h"   // for VIANIUM_MTPROXY_API

namespace vianium { namespace mtproxy {

// =============================================================================
// AES-256-CTR keystream XOR.
//
// MTProxy's obfuscation layer is AES-256-CTR with a 16-byte IV that
// doubles as the counter block. The counter is interpreted as a
// 128-bit big-endian integer that increments by one for every block
// of keystream consumed.
//
// `iv` is updated in place so that successive calls continue the same
// stream — i.e. the caller owns the cipher state across reads/writes
// from the same direction.
// =============================================================================

VIANIUM_MTPROXY_API void AesCtrXorInPlace(const uint8_t key[32],
                      uint8_t       iv [16],   // mutated in place
                      uint8_t*      data,
                      size_t        length);

}}  // namespace vianium::mtproxy
