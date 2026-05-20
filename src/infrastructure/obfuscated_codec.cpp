// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "pch.h"
#include "obfuscated_codec.h"

// AES core from vianium-crypto. The actual API is a class:
//
//   namespace vianium::crypto {
//     class AesKey {
//       public:
//         void Init(const uint8_t* key, int keyLen);
//         void EncryptBlock(const uint8_t in[16], uint8_t out[16]) const;
//     };
//   }
//
// We only need AES-256 single-block encryption — the CTR mode is built
// on top by XOR-ing the encrypted counter into the data buffer.
#include <vianium/crypto/aes_core.h>

#include <cstring>

namespace vianium { namespace mtproxy {

// Increment a 16-byte big-endian counter (the IV-as-counter convention
// used by MTProxy, matching the Telegram reference servers).
static void IncrementCounterBE(uint8_t counter[16])
{
    for (int i = 15; i >= 0; --i)
    {
        uint8_t prev = counter[i]++;
        if (prev != 0xFFu) break;
    }
}

void AesCtrXorInPlace(const uint8_t key[32],
                      uint8_t       iv [16],
                      uint8_t*      data,
                      size_t        length)
{
    if (length == 0) return;

    vianium::crypto::AesKey aes;
    aes.Init(key, 32);   // 32 bytes = AES-256

    uint8_t counter[16];
    std::memcpy(counter, iv, 16);

    uint8_t keystream[16];

    size_t produced = 0;
    while (produced < length)
    {
        aes.EncryptBlock(counter, keystream);

        size_t take = length - produced;
        if (take > 16) take = 16;

        for (size_t i = 0; i < take; ++i) data[produced + i] ^= keystream[i];

        IncrementCounterBE(counter);
        produced += take;
    }

    // Persist the advanced counter back to the caller's IV slot so the
    // next call continues the same keystream.
    std::memcpy(iv, counter, 16);
}

}}  // namespace vianium::mtproxy
