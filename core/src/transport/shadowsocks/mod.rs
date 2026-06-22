//! Shadowsocks 2022 (SIP022) transport (ADR 0009): a pre-shared-key AEAD tunnel, wire-interoperable
//! with deployed shadowsocks-rust / sing-box SS-2022 servers. TCP (three `2022-blake3-*` ciphers) +
//! UDP (the two AES methods). See `docs/shadowsocks-design.md`.

mod crypto;
mod tcp;
mod udp;
