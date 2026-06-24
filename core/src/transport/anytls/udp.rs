//! UDP over AnyTLS via sing-box **UDP-over-TCP v2** (feature `anytls`).
//!
//! AnyTLS conveys a stream's destination in-band as a SOCKS5 address, so a UDP association is just a
//! fresh pooled stream whose target is the UoT magic address. This writes that magic target, then
//! hands the stream to the shared [`crate::transport::uot`] framing (verified against `sing/common/uot`).

use std::io;
use std::net::SocketAddr;

use bytes::BytesMut;
use tokio::io::AsyncWriteExt;

use crate::transport::tcp_tunnel::header::Address;
use crate::transport::uot::{self, UOT_MAGIC};
use crate::transport::{BoxedPacketSink, BoxedPacketSource};

use super::Stream;

/// Establish a UoT v2 connected association to `target` over an AnyTLS `stream`: write the magic
/// address as the stream's SOCKS5 target (so the server treats it as a UDP association), then run the
/// shared UoT framing (connect request + `[u16 BE len][payload]` datagrams).
pub async fn associate(
    mut stream: Stream,
    target: SocketAddr,
) -> io::Result<(BoxedPacketSink, BoxedPacketSource)> {
    let mut hdr = BytesMut::new();
    Address::Domain {
        host: UOT_MAGIC.to_owned(),
        port: 0,
    }
    .encode(&mut hdr);
    stream.write_all(&hdr).await?;
    uot::associate(stream, target).await
}
