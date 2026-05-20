// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Symbols below are consumed by external native code (notably
// vianium-mtproto's MtProxyTcpTransport). Mark them with dll linkage so
// the import .lib carries them when this DLL is built; we'd otherwise
// only export the C bridge in src/infrastructure/c_bridge.cpp.
#if defined(_WIN32)
#if defined(VIANIUM_MTPROXY_EXPORTS)
#define VIANIUM_MTPROXY_API __declspec(dllexport)
#else
#define VIANIUM_MTPROXY_API __declspec(dllimport)
#endif
#else
#define VIANIUM_MTPROXY_API
#endif

namespace vianium { namespace mtproxy {

// =============================================================================
// MtProxySecret — parses every secret format Telegram clients accept.
// =============================================================================
//
//   * Legacy mode      — 32 hex chars        (16 raw bytes)
//   * Secure mode      — "dd" + 32 hex chars (1 flag byte 0xDD + 16 raw bytes)
//   * fakeTLS mode     — "ee" + 32 hex chars + ASCII domain bytes
//                        (1 flag byte 0xEE + 16 raw bytes + N-byte SNI)
//   * URL-safe base64  — same as the above, but base64url-encoded
//
// The wire-level secret is always 16 bytes; the prefix byte and trailing
// domain bytes drive mode dispatch.
//
// Source of truth: https://core.telegram.org/mtproto/mtproto-transports
// =============================================================================

enum class MtProxySecretMode
{
    Legacy   = 0,   // 16-byte raw secret, no prefix
    Secure   = 1,   // 0xDD flag — secure-only random padding intermediate proto
    FakeTls  = 2    // 0xEE flag — fake-TLS-1.3 ClientHello wrapper + SNI
};

class MtProxySecret
{
public:
    // ------------------------------------------------------------------
    // Parse. Accepts hex (lowercase or upper) or url-safe base64
    // ("-_" instead of "+/", optional "=" padding).
    // Returns true and populates *out on success; false otherwise.
    // ------------------------------------------------------------------
    static VIANIUM_MTPROXY_API bool TryParse(const std::string& text, MtProxySecret* out);

    // Convenience: throws std::invalid_argument on parse failure.
    static VIANIUM_MTPROXY_API MtProxySecret Parse(const std::string& text);

    // Direct constructors (no parsing).
    static VIANIUM_MTPROXY_API MtProxySecret FromLegacyBytes(const uint8_t bytes[16]);
    static VIANIUM_MTPROXY_API MtProxySecret FromSecureBytes(const uint8_t bytes[16]);
    static VIANIUM_MTPROXY_API MtProxySecret FromFakeTls(const uint8_t bytes[16], const std::string& sni_domain);

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------
    MtProxySecretMode Mode() const { return mode_; }
    const uint8_t* Bytes() const { return secret_bytes_; }   // 16-byte buffer
    const std::string& FakeTlsDomain() const { return fake_tls_domain_; }

    // Re-encode in canonical hex form (with mode prefix where applicable).
    std::string ToHex() const;

private:
    MtProxySecret() : mode_(MtProxySecretMode::Legacy) { std::memset(secret_bytes_, 0, 16); }

    MtProxySecretMode mode_;
    uint8_t           secret_bytes_[16];
    std::string       fake_tls_domain_;   // populated only in FakeTls mode
};

// =============================================================================
// Hex / base64 helpers — exposed for the smoke tests.
// =============================================================================

// Returns true if every char is in [0-9a-fA-F] and length is even.
bool IsValidHex(const std::string& text);

// Decodes hex into out. Returns false on invalid input. out is sized to
// text.size() / 2 on success.
bool HexDecode(const std::string& text, std::vector<uint8_t>* out);

// Decodes url-safe base64. Returns false on invalid input.
bool Base64UrlDecode(const std::string& text, std::vector<uint8_t>* out);

}}  // namespace vianium::mtproxy
