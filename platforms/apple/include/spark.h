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
 * `server` selects the data path: NULL (or empty) forwards each flow DIRECTLY to its destination;
 * a "host:port" IP literal (e.g. "203.0.113.4:9000") tunnels every flow through that plain spark
 * relay, so egress is the relay's IP. A malformed `server` returns -1. */
int32_t spark_tunnel_run(int32_t fd, int32_t mtu, const char *server);

/* Signal a running spark_tunnel_run() to stop. */
void spark_tunnel_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* SPARK_H */
