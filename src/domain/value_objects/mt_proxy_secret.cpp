// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Angel Careaga <hello@angelcareaga.com>

#include "pch.h"
#include "../../domain/value_objects/mt_proxy_secret.h"

#include <cctype>
#include <stdexcept>

namespace vianium { namespace mtproxy {

// -----------------------------------------------------------------------------
// Hex helpers
// -----------------------------------------------------------------------------

bool IsValidHex(const std::string& text)
{
    if ((text.size() % 2) != 0) return false;
    for (size_t i = 0; i < text.size(); ++i)
    {
        char c = text[i];
        bool is_digit = (c >= '0' && c <= '9');
        bool is_lower = (c >= 'a' && c <= 'f');
        bool is_upper = (c >= 'A' && c <= 'F');
        if (!is_digit && !is_lower && !is_upper) return false;
    }
    return true;
}

static int HexNibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool HexDecode(const std::string& text, std::vector<uint8_t>* out)
{
    if (!IsValidHex(text)) return false;
    out->clear();
    out->reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2)
    {
        int hi = HexNibble(text[i]);
        int lo = HexNibble(text[i + 1]);
        out->push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

// -----------------------------------------------------------------------------
// Base64-url helpers
// -----------------------------------------------------------------------------

static int Base64UrlChar(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

bool Base64UrlDecode(const std::string& text, std::vector<uint8_t>* out)
{
    // Strip optional padding.
    size_t end = text.size();
    while (end > 0 && text[end - 1] == '=') --end;
    if ((end % 4) == 1) return false;  // illegal length class

    out->clear();
    out->reserve((end * 3) / 4);

    uint32_t accum = 0;
    int      bits  = 0;
    for (size_t i = 0; i < end; ++i)
    {
        int v = Base64UrlChar(text[i]);
        if (v < 0) return false;
        accum = (accum << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out->push_back(static_cast<uint8_t>((accum >> bits) & 0xFF));
        }
    }
    return true;
}

// -----------------------------------------------------------------------------
// MtProxySecret
// -----------------------------------------------------------------------------

bool MtProxySecret::TryParse(const std::string& text, MtProxySecret* out)
{
    if (text.empty() || out == nullptr) return false;

    // Attempt hex decode first; if the input is not hex, fall back to
    // base64-url. Both encodings target the same byte stream.
    std::vector<uint8_t> raw;
    if (!HexDecode(text, &raw))
    {
        if (!Base64UrlDecode(text, &raw)) return false;
    }

    if (raw.empty()) return false;

    // -------- Mode dispatch by first byte --------
    // Legacy   : exactly 16 raw bytes, no prefix.
    // Secure   : 17 bytes; raw[0] == 0xDD, raw[1..16] is the secret.
    // FakeTls  : 17+N bytes; raw[0] == 0xEE, raw[1..16] is the secret,
    //            raw[17..] is the SNI domain (ASCII).
    if (raw.size() == 16)
    {
        out->mode_ = MtProxySecretMode::Legacy;
        std::memcpy(out->secret_bytes_, raw.data(), 16);
        out->fake_tls_domain_.clear();
        return true;
    }

    if (raw.size() >= 17 && raw[0] == 0xDD && raw.size() == 17)
    {
        out->mode_ = MtProxySecretMode::Secure;
        std::memcpy(out->secret_bytes_, raw.data() + 1, 16);
        out->fake_tls_domain_.clear();
        return true;
    }

    if (raw.size() >= 17 && raw[0] == 0xEE)
    {
        out->mode_ = MtProxySecretMode::FakeTls;
        std::memcpy(out->secret_bytes_, raw.data() + 1, 16);
        const size_t domain_offset = 17;
        if (raw.size() > domain_offset)
        {
            out->fake_tls_domain_.assign(
                reinterpret_cast<const char*>(raw.data() + domain_offset),
                raw.size() - domain_offset);
        }
        else
        {
            out->fake_tls_domain_.clear();
        }
        return true;
    }

    return false;
}

MtProxySecret MtProxySecret::Parse(const std::string& text)
{
    MtProxySecret out;
    if (!TryParse(text, &out))
        throw std::invalid_argument("MtProxySecret: malformed secret '" + text + "'");
    return out;
}

MtProxySecret MtProxySecret::FromLegacyBytes(const uint8_t bytes[16])
{
    MtProxySecret out;
    out.mode_ = MtProxySecretMode::Legacy;
    std::memcpy(out.secret_bytes_, bytes, 16);
    return out;
}

MtProxySecret MtProxySecret::FromSecureBytes(const uint8_t bytes[16])
{
    MtProxySecret out;
    out.mode_ = MtProxySecretMode::Secure;
    std::memcpy(out.secret_bytes_, bytes, 16);
    return out;
}

MtProxySecret MtProxySecret::FromFakeTls(const uint8_t bytes[16], const std::string& sni)
{
    MtProxySecret out;
    out.mode_             = MtProxySecretMode::FakeTls;
    std::memcpy(out.secret_bytes_, bytes, 16);
    out.fake_tls_domain_ = sni;
    return out;
}

static char ToHexNibble(uint8_t v)
{
    return static_cast<char>(v < 10 ? '0' + v : 'a' + (v - 10));
}

static void AppendHex(std::string& out, uint8_t b)
{
    out += ToHexNibble(static_cast<uint8_t>(b >> 4));
    out += ToHexNibble(static_cast<uint8_t>(b & 0x0F));
}

std::string MtProxySecret::ToHex() const
{
    std::string out;
    switch (mode_)
    {
        case MtProxySecretMode::Legacy:
            // no prefix
            break;
        case MtProxySecretMode::Secure:
            AppendHex(out, 0xDD);
            break;
        case MtProxySecretMode::FakeTls:
            AppendHex(out, 0xEE);
            break;
    }
    for (size_t i = 0; i < 16; ++i) AppendHex(out, secret_bytes_[i]);
    if (mode_ == MtProxySecretMode::FakeTls)
    {
        for (size_t i = 0; i < fake_tls_domain_.size(); ++i)
            AppendHex(out, static_cast<uint8_t>(fake_tls_domain_[i]));
    }
    return out;
}

}}  // namespace vianium::mtproxy
