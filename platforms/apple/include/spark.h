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

/* ---- Server selection (multi-server pool) ----
 * The controlling app drives these via the NE provider's handleAppMessage. They operate on the
 * pool of the currently-running tunnel; with no active pool (direct / single relay / AnyTLS) they
 * report an empty list / failure rather than erroring. */

/* The active server pool as a JSON array, camelCase keys:
 *   [{"index":0,"name":"sfo3","country":"United States","countryCode":"US",
 *     "city":"San Francisco","latencyMs":19,"healthy":true,"isCurrent":true}, ...]
 * Returns "[]" when no pool is active. The result is heap-allocated — free it with
 * spark_string_free(). Returns NULL only on allocation failure. */
char *spark_servers_json(void);

/* Free a string returned by spark_servers_json(). A NULL argument is ignored. */
void spark_string_free(char *s);

/* Pin which pool member new flows dial first: index >= 0 pins that member (overriding the latency
 * ranking); index < 0 selects auto (latency-ranked). Affects new flows only. Returns 0 on success,
 * -1 if no server pool is active. */
int32_t spark_select_server(int32_t index);

#ifdef __cplusplus
}
#endif

#endif /* SPARK_H */
