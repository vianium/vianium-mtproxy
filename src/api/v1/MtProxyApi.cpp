// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "pch.h"
#include "MtProxyApi.h"

#include "../../domain/value_objects/mt_proxy_secret.h"
#include "../../domain/value_objects/handshake_init.h"
#include "../../infrastructure/obfuscated_codec.h"

#include <cstring>

using namespace Platform;

namespace Vianium {
namespace MtProxy {
namespace Api {
namespace V1 {

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

static std::string ToStdString(Platform::String^ s)
{
    if (s == nullptr) return std::string();
    std::wstring w(s->Data(), s->Length());
    std::string out;
    out.reserve(w.size());
    for (size_t i = 0; i < w.size(); ++i)
        out.push_back(static_cast<char>(w[i] & 0xFF));
    return out;
}

static Platform::String^ ToPlatformString(const std::string& s)
{
    std::wstring w;
    w.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i)
        w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(s[i])));
    return ref new Platform::String(w.data(), static_cast<unsigned int>(w.size()));
}

// =============================================================================
// MtProxySecret
// =============================================================================

MtProxySecret::MtProxySecret() : _mode(0), _fakeTlsDomain(nullptr)
{
    _bytes = ref new Platform::Array<uint8>(16);
    std::memset(_bytes->Data, 0, 16);
}

void MtProxySecret::Adopt(int mode, const uint8_t bytes[16], Platform::String^ fake_tls_domain)
{
    _mode = mode;
    std::memcpy(_bytes->Data, bytes, 16);
    _fakeTlsDomain = fake_tls_domain;
}

MtProxySecret^ MtProxySecret::Parse(Platform::String^ text)
{
    auto out = TryParse(text);
    if (out == nullptr)
        throw ref new Platform::InvalidArgumentException(L"MtProxySecret: malformed secret");
    return out;
}

MtProxySecret^ MtProxySecret::TryParse(Platform::String^ text)
{
    // MtProxySecret has a private default ctor (its invariant is "always
    // built via a factory"). Seed via FromLegacyBytes(zeros) so we have
    // a valid instance; TryParse overwrites through copy-assignment.
    uint8_t mtproxy_secret_seed_zeros[16] = {0};
    vianium::mtproxy::MtProxySecret native =
        vianium::mtproxy::MtProxySecret::FromLegacyBytes(mtproxy_secret_seed_zeros);
    if (!vianium::mtproxy::MtProxySecret::TryParse(ToStdString(text), &native))
        return nullptr;

    auto out = ref new MtProxySecret();
    out->Adopt(static_cast<int>(native.Mode()), native.Bytes(),
               ToPlatformString(native.FakeTlsDomain()));
    return out;
}

SecretMode MtProxySecret::Mode::get()
{
    return static_cast<SecretMode>(_mode);
}

Platform::Array<uint8>^ MtProxySecret::Bytes::get()
{
    auto copy = ref new Platform::Array<uint8>(16);
    std::memcpy(copy->Data, _bytes->Data, 16);
    return copy;
}

Platform::String^ MtProxySecret::FakeTlsDomain::get()
{
    return _fakeTlsDomain;
}

Platform::String^ MtProxySecret::ToHex()
{
    // The switch always overwrites `native` via copy-assignment from a
    // factory call, but the local must be seeded with a factory result
    // (the default ctor is private). Pick FromLegacyBytes(zeros) — cheap
    // and immediately replaced.
    uint8_t mtproxy_secret_seed_zeros[16] = {0};
    vianium::mtproxy::MtProxySecret native =
        vianium::mtproxy::MtProxySecret::FromLegacyBytes(mtproxy_secret_seed_zeros);
    switch (_mode)
    {
        case 0: native = vianium::mtproxy::MtProxySecret::FromLegacyBytes(_bytes->Data); break;
        case 1: native = vianium::mtproxy::MtProxySecret::FromSecureBytes(_bytes->Data); break;
        case 2: native = vianium::mtproxy::MtProxySecret::FromFakeTls(_bytes->Data,
                                                                     ToStdString(_fakeTlsDomain)); break;
        default: native = vianium::mtproxy::MtProxySecret::FromLegacyBytes(_bytes->Data); break;
    }
    return ToPlatformString(native.ToHex());
}

// =============================================================================
// HandshakeOutput
// =============================================================================

HandshakeOutput::HandshakeOutput()
{
    _init   = ref new Platform::Array<uint8>(64);
    _encKey = ref new Platform::Array<uint8>(32);
    _encIv  = ref new Platform::Array<uint8>(16);
    _decKey = ref new Platform::Array<uint8>(32);
    _decIv  = ref new Platform::Array<uint8>(16);
}

void HandshakeOutput::Adopt(const uint8_t init[64],
                            const uint8_t ek  [32],
                            const uint8_t ei  [16],
                            const uint8_t dk  [32],
                            const uint8_t di  [16])
{
    std::memcpy(_init->Data,   init, 64);
    std::memcpy(_encKey->Data, ek,   32);
    std::memcpy(_encIv->Data,  ei,   16);
    std::memcpy(_decKey->Data, dk,   32);
    std::memcpy(_decIv->Data,  di,   16);
}

Platform::Array<uint8>^ HandshakeOutput::InitPacket::get()
{
    auto copy = ref new Platform::Array<uint8>(64);
    std::memcpy(copy->Data, _init->Data, 64);
    return copy;
}

Platform::Array<uint8>^ HandshakeOutput::EncryptKey::get()
{
    auto copy = ref new Platform::Array<uint8>(32);
    std::memcpy(copy->Data, _encKey->Data, 32);
    return copy;
}

Platform::Array<uint8>^ HandshakeOutput::EncryptIv::get()
{
    auto copy = ref new Platform::Array<uint8>(16);
    std::memcpy(copy->Data, _encIv->Data, 16);
    return copy;
}

Platform::Array<uint8>^ HandshakeOutput::DecryptKey::get()
{
    auto copy = ref new Platform::Array<uint8>(32);
    std::memcpy(copy->Data, _decKey->Data, 32);
    return copy;
}

Platform::Array<uint8>^ HandshakeOutput::DecryptIv::get()
{
    auto copy = ref new Platform::Array<uint8>(16);
    std::memcpy(copy->Data, _decIv->Data, 16);
    return copy;
}

// =============================================================================
// HandshakeBuilder
// =============================================================================

bool HandshakeBuilder::IsValidRandomness(const Platform::Array<uint8>^ randomness)
{
    if (randomness == nullptr || randomness->Length < 58) return false;
    return vianium::mtproxy::HandshakeInit::IsValidRandomness(randomness->Data);
}

HandshakeOutput^ HandshakeBuilder::Build(MtProxySecret^ secret,
                                         ProtocolMarker proto,
                                         int            dcId,
                                         const Platform::Array<uint8>^ randomness)
{
    if (secret == nullptr || randomness == nullptr || randomness->Length < 58)
        return nullptr;

    // Rehydrate the native secret from the WinRT view. We round-trip
    // through ToHex/TryParse to avoid a friend-class dependency. Seed
    // with FromLegacyBytes(zeros) so the local has a valid default
    // (private ctor); TryParse overwrites via copy-assignment on success.
    uint8_t mtproxy_secret_seed_zeros[16] = {0};
    vianium::mtproxy::MtProxySecret native_secret =
        vianium::mtproxy::MtProxySecret::FromLegacyBytes(mtproxy_secret_seed_zeros);
    auto secret_hex = secret->ToHex();
    if (!vianium::mtproxy::MtProxySecret::TryParse(ToStdString(secret_hex), &native_secret))
        return nullptr;

    vianium::mtproxy::HandshakeOutput native_out;
    bool ok = vianium::mtproxy::HandshakeInit::Build(
        native_secret,
        static_cast<uint32_t>(proto),
        static_cast<int16_t>(dcId),
        randomness->Data,
        &native_out);
    if (!ok) return nullptr;

    auto winrt_out = ref new HandshakeOutput();
    winrt_out->Adopt(native_out.init_packet,
                     native_out.keys.encrypt_key,
                     native_out.keys.encrypt_iv,
                     native_out.keys.decrypt_key,
                     native_out.keys.decrypt_iv);
    return winrt_out;
}

// =============================================================================
// ObfuscatedCodec
// =============================================================================

ObfuscatedCodec::ObfuscatedCodec(const Platform::Array<uint8>^ key,
                                 const Platform::Array<uint8>^ iv)
{
    if (key == nullptr || key->Length < 32)
        throw ref new Platform::InvalidArgumentException(L"ObfuscatedCodec: key must be 32 bytes");
    if (iv  == nullptr || iv->Length  < 16)
        throw ref new Platform::InvalidArgumentException(L"ObfuscatedCodec: iv must be 16 bytes");

    _key = ref new Platform::Array<uint8>(32);
    _iv  = ref new Platform::Array<uint8>(16);
    std::memcpy(_key->Data, key->Data, 32);
    std::memcpy(_iv->Data,  iv->Data,  16);
}

void ObfuscatedCodec::XorInPlace(Platform::WriteOnlyArray<uint8>^ buffer)
{
    if (buffer == nullptr || buffer->Length == 0) return;

    vianium::mtproxy::AesCtrXorInPlace(
        _key->Data,
        _iv->Data,
        buffer->Data,
        buffer->Length);
}

}}}}   // namespace Vianium::MtProxy::Api::V1
