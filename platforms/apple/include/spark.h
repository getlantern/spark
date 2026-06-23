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
 * `config` selects the data path:
 *   - NULL/empty            -> forward each flow DIRECTLY (no tunnel).
 *   - "lantern-api"         -> self-fetch config from the Lantern config-new API into `data_dir`
 *                              (the app-group container path) and run the tunnel from it, refreshing
 *                              in the background. Requires the `config-fetch` feature (macOS slice
 *                              only); the iOS slice returns -1. `data_dir` must be non-NULL in this
 *                              mode — it caches device_id and the fetched config.
 *   - a "host:port" literal -> tunnel every flow through that plain spark relay.
 *   - any other string      -> a full Config: spark's native TOML or a Lantern config_raw.json
 *                              payload, auto-detected (AnyTLS + handshake shaping + gambit, ...).
 * AnyTLS requires the staticlib built with the `anytls` feature (the macOS slice is). A string that
 * is neither "lantern-api", a host:port, nor a valid TOML/config_raw.json config returns -1.
 *
 * `data_dir` must be NULL or a valid NUL-terminated C string for the duration of this call. */
int32_t spark_tunnel_run(int32_t fd, int32_t mtu, const char *config, const char *data_dir);

/* Signal a running spark_tunnel_run() to stop. */
void spark_tunnel_stop(void);

/* Readiness gating, so the provider doesn't report the tunnel "up" before the data path is actually
 * servicing the fd (notably `lantern-api` cold-start, which fetches config before adopting the fd —
 * reporting up too early blackholes traffic). Usage in startTunnel:
 *   1. call spark_tunnel_mark_connecting() SYNCHRONOUSLY, before spawning the spark_tunnel_run worker;
 *   2. on a separate thread, call spark_tunnel_wait_ready(timeout_ms);
 *   3. on 0 -> completionHandler(nil); on -1 -> spark_tunnel_stop() + fail the connection. */
void spark_tunnel_mark_connecting(void);

/* Block until the data path is up (0) or it doesn't come up within timeout_ms / stops first (-1). */
int32_t spark_tunnel_wait_ready(int32_t timeout_ms);

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
