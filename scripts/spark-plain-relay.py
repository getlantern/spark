#!/usr/bin/env python3
"""Minimal relay server for spark's plain TCP tunnel transport (the M4 wire protocol).

The spark client connects, writes a SOCKS5-style target-address header
(ATYP(1) | ADDR | PORT(2, big-endian); ATYP 1=IPv4, 3=domain[len-prefixed], 4=IPv6) — see
core/src/transport/tcp_tunnel/header.rs — then relays raw bytes. There is no server reply; we
parse the header, dial the target, and splice both directions. Egress is therefore this host's IP.

TCP only (the gate routes a single TCP dst into the tun; DNS/UDP stay direct). Throwaway test
server — plaintext, no auth. Run: python3 spark-plain-relay.py [host] [port]   (default 0.0.0.0:9000)
"""
import asyncio
import socket
import struct
import sys


async def read_target(reader: asyncio.StreamReader):
    atyp = (await reader.readexactly(1))[0]
    if atyp == 1:  # IPv4
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif atyp == 4:  # IPv6
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    elif atyp == 3:  # domain
        dlen = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(dlen)).decode("utf-8", "strict")
    else:
        raise ValueError(f"unknown ATYP {atyp}")
    port = struct.unpack(">H", await reader.readexactly(2))[0]
    return host, port


async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    try:
        while True:
            data = await r.read(65536)
            if not data:
                break
            w.write(data)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        host, port = await read_target(reader)
    except Exception as e:
        print(f"[relay] {peer} bad header: {e}", flush=True)
        writer.close()
        return
    try:
        tr, tw = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
    except Exception as e:
        print(f"[relay] {peer} -> {host}:{port} dial failed: {e}", flush=True)
        writer.close()
        return
    print(f"[relay] {peer} -> {host}:{port} connected", flush=True)
    await asyncio.gather(pipe(reader, tw), pipe(tr, writer))


async def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9000
    server = await asyncio.start_server(handle, host, port)
    print(f"[relay] listening on {host}:{port}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
