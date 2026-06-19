/* spark-apple C ABI — the NetworkExtension Packet Tunnel Provider calls these.
 * Linked from libspark_apple.a (packaged as an .xcframework). Control-only: packets never
 * cross this boundary — Rust owns the utun fd and runs the whole netstack. */
#ifndef SPARK_H
#define SPARK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Run the tunnel on the provided utun `fd` with `mtu`. Blocks the calling thread until
 * spark_tunnel_stop() (or the data path exits). Returns 0 on a clean stop, -1 on error.
 * Ownership of `fd` is transferred to native; it is closed on stop.
 *
 * `config` selects the data path (dual-mode):
 *   - NULL/empty           -> forward each flow DIRECTLY (no tunnel).
 *   - a "host:port" literal -> tunnel every flow through that plain spark relay.
 *   - any other string      -> a full TOML config (AnyTLS + handshake shaping + gambit, ...).
 * AnyTLS requires the staticlib built with the `anytls` feature (the macOS slice is). A string that
 * is neither a host:port nor valid TOML returns -1. */
int32_t spark_tunnel_run(int32_t fd, int32_t mtu, const char *config);

/* Signal a running spark_tunnel_run() to stop. */
void spark_tunnel_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* SPARK_H */
