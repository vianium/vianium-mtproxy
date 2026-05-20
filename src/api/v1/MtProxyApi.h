// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <collection.h>

namespace Vianium {
namespace MtProxy {
namespace Api {
namespace V1 {

// =============================================================================
// WinRT projection of the MTProxy obfuscated transport.
//
// Consumers (managed C# / WinRT) reach the underlying native protocol
// through these ref classes. The native types live in
//   src\domain\value_objects   and   src\infrastructure
// and are unconditionally `internal` to the assembly; the WinRT layer
// is the only public surface.
// =============================================================================

public enum class SecretMode : int
{
    Legacy  = 0,
    Secure  = 1,
    FakeTls = 2
};

// NOTE on underlying type: we use signed `int` rather than `unsigned int`
// here. With an unsigned underlying type the C++/CX compiler heuristic
// auto-applies [FlagsAttribute] when the values look like bit patterns
// (the 0xEF/EE/DD high-byte triplets do), which then trips C2916 because
// not all values are powers-of-two. Using `int` disables that heuristic;
// the bit patterns are preserved verbatim via the static_cast.
public enum class ProtocolMarker : int
{
    Abridged           = static_cast<int>(0xEFEFEFEFu),
    Intermediate       = static_cast<int>(0xEEEEEEEEu),
    PaddedIntermediate = static_cast<int>(0xDDDDDDDDu)
};

// -----------------------------------------------------------------------------
// MtProxySecret — parses and represents a Telegram MTProxy secret.
// -----------------------------------------------------------------------------

public ref class MtProxySecret sealed
{
public:
    // Throws Platform::InvalidArgumentException on malformed input.
    static MtProxySecret^ Parse(Platform::String^ text);

    // Returns nullptr on malformed input — useful when the secret comes
    // from user-typed UI and "parse failure" is the normal error path.
    static MtProxySecret^ TryParse(Platform::String^ text);

    property SecretMode                       Mode          { SecretMode get(); }
    property Platform::Array<uint8>^          Bytes         { Platform::Array<uint8>^ get(); }   // 16 bytes
    property Platform::String^                FakeTlsDomain { Platform::String^ get(); }

    Platform::String^ ToHex();

internal:
    // Internal construction path used by the implementation.
    MtProxySecret();
    void Adopt(int mode, const uint8_t bytes[16], Platform::String^ fake_tls_domain);

private:
    int                _mode;
    Platform::Array<uint8>^ _bytes;
    Platform::String^  _fakeTlsDomain;
};

// -----------------------------------------------------------------------------
// HandshakeOutput — 64-byte init packet + 4 AES-CTR materials.
// -----------------------------------------------------------------------------

public ref class HandshakeOutput sealed
{
public:
    property Platform::Array<uint8>^ InitPacket { Platform::Array<uint8>^ get(); }   // 64 bytes
    property Platform::Array<uint8>^ EncryptKey { Platform::Array<uint8>^ get(); }   // 32 bytes
    property Platform::Array<uint8>^ EncryptIv  { Platform::Array<uint8>^ get(); }   // 16 bytes
    property Platform::Array<uint8>^ DecryptKey { Platform::Array<uint8>^ get(); }   // 32 bytes
    property Platform::Array<uint8>^ DecryptIv  { Platform::Array<uint8>^ get(); }   // 16 bytes

internal:
    HandshakeOutput();
    void Adopt(const uint8_t init_packet[64],
               const uint8_t enc_key   [32],
               const uint8_t enc_iv    [16],
               const uint8_t dec_key   [32],
               const uint8_t dec_iv    [16]);

private:
    Platform::Array<uint8>^ _init;
    Platform::Array<uint8>^ _encKey;
    Platform::Array<uint8>^ _encIv;
    Platform::Array<uint8>^ _decKey;
    Platform::Array<uint8>^ _decIv;
};

// -----------------------------------------------------------------------------
// HandshakeBuilder — pure builder, no I/O.
// -----------------------------------------------------------------------------

public ref class HandshakeBuilder sealed
{
public:
    // Returns true when the 58-byte randomness draw passes the
    // wire-format constraints. Callers should re-draw on false.
    static bool IsValidRandomness(const Platform::Array<uint8>^ randomness);

    // Builds the init packet + AES-CTR keys from a secret, protocol
    // selector, dc_id, and 58 random bytes. Returns nullptr if the
    // randomness fails IsValidRandomness().
    static HandshakeOutput^ Build(MtProxySecret^ secret,
                                  ProtocolMarker proto,
                                  int            dcId,
                                  const Platform::Array<uint8>^ randomness);
};

// -----------------------------------------------------------------------------
// ObfuscatedCodec — stateful AES-256-CTR XOR over the wire stream.
//
// One codec per direction. Construct with the (key, iv) pair derived
// by HandshakeBuilder and then call XorInPlace on every chunk you read
// or write. Successive calls continue the same keystream.
// -----------------------------------------------------------------------------

public ref class ObfuscatedCodec sealed
{
public:
    // key  : 32 bytes (AES-256)
    // iv   : 16 bytes (used as the initial counter block)
    ObfuscatedCodec(const Platform::Array<uint8>^ key,
                    const Platform::Array<uint8>^ iv);

    // XOR the buffer in place against the current keystream window.
    // After the call, the codec has advanced its internal counter so
    // the next XorInPlace continues the stream.
    void XorInPlace(Platform::WriteOnlyArray<uint8>^ buffer);

private:
    Platform::Array<uint8>^ _key;
    Platform::Array<uint8>^ _iv;   // mutates each call
};

}}}}   // namespace Vianium::MtProxy::Api::V1
