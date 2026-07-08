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
 * The daemon owns config acquisition: the ABSENCE of an explicit config is the signal to self-fetch
 * (the fetch must bypass the tunnel, which only the extension can guarantee). The Apple staticlib
 * carries `config-fetch` on EVERY slice (iOS device, iOS simulator, macOS — BoringSSL cross-compiles
 * for all), so self-fetch works identically across them. `config` selects the data path:
 *   - NULL/empty            -> SELF-FETCH config from the Lantern config-new API into `data_dir` (the
 *                              app-group container) and run from it, refreshing in the background;
 *                              `data_dir` must be non-NULL (else the connect fails).
 *   - "lantern-api"         -> explicit alias for the self-fetch above.
 *   - an "IP:port" literal -> tunnel every flow through that plain spark relay (IP only, not a
 *                              hostname; SocketAddr-parsed). Explicit override, e.g. dev/testing.
 *   - any other string      -> a full Config: spark's native TOML or a Lantern config_raw.json
 *                              payload, auto-detected (AnyTLS + handshake shaping + gambit, ...).
 * The fetch + AnyTLS use the BoringSSL `anytls` backend, which every Apple slice carries. A non-empty
 * explicit string -- other than the reserved "lantern-api" sentinel above -- that is neither an
 * IP:port nor a valid TOML/config_raw.json config returns -1.
 *
 * `data_dir` must be NULL or a valid NUL-terminated C string for the duration of this call.
 *
 * `split_tunnel` is an optional NUL-terminated `{enabled,domains,ips}` JSON payload that
 * initialises the split-tunnel bypass list. NULL disables split-tunneling at startup. A bad
 * or non-UTF-8 value is silently ignored (treated as NULL) — the bypass list is non-critical
 * and must not prevent the tunnel from starting.
 *
 * `routing_mode` is an optional NUL-terminated "smart"/"full" string that sets the initial
 * routing mode. NULL defaults to the core's built-in default. A bad or non-UTF-8 value is
 * silently ignored (treated as NULL) — the routing mode is non-critical and must not prevent
 * the tunnel from starting. */
int32_t spark_tunnel_run(int32_t fd, int32_t mtu, const char *config, const char *data_dir,
                         const char *split_tunnel, const char *routing_mode);

/* Signal a running spark_tunnel_run() to stop. */
void spark_tunnel_stop(void);

/* Bridge the Rust core's tracing events to a host logger. Without this the NE has no tracing
 * subscriber and every core info!/warn! (the whole config-fetch path) is dropped, leaving on-device
 * debugging blind. Call ONCE at startup, BEFORE spark_tunnel_run(), so cold-start fetch logs are
 * captured. `cb` receives (level, msg): level is 0=ERROR,1=WARN,2=INFO,3=DEBUG,4=TRACE. By default
 * DEBUG and more severe are forwarded (for spark's own targets only, so TRACE is dropped and
 * dependency-internal noise is filtered out); `msg` is a NUL-terminated UTF-8 string valid ONLY for
 * the duration of the call — copy it synchronously (e.g. String(cString:)). A NULL `cb` is ignored;
 * idempotent. */
typedef void (*spark_log_cb)(uint8_t level, const char *msg);
void spark_set_log_callback(spark_log_cb cb);

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

/* ---- Split-tunnel bypass list ----
 * Update the running tunnel's split-tunnel bypass list live. `json` is a NUL-terminated
 * `{enabled,domains,ips}` payload. Returns 0 if applied; -1 if `json` is NULL, not valid UTF-8,
 * not valid JSON, or there is no active router to update (no tunnel running, or a tunnel running
 * without smart-routing — e.g. a plain relay/proxy path has no router). */
int32_t spark_set_split_tunnel(const char *json);

/* ---- App-bypass list (desktop app split tunneling) ----
 * Live-push the app-bypass list to the running tunnel. `json` is a NUL-terminated JSON array of
 * canonical `.app` bundle-root paths (["/Applications/Foo.app", ...]), matched by prefix against
 * the resolved process path so in-bundle helpers match too — NOT executable paths; the listed apps
 * route Direct (absolute). Returns 0 if applied; -1 if `json` is NULL, not valid UTF-8, not valid
 * JSON, or there is no active router to update (no tunnel running, or a tunnel running without
 * smart-routing — e.g. a plain relay/proxy path has no router). */
int32_t spark_set_app_bypass(const char *json);

/* Update the running tunnel's routing mode live. `mode` is a NUL-terminated "smart"/"full".
 * Returns 0 if applied; -1 if `mode` is NULL, not valid UTF-8, or there is no active router to
 * update (no tunnel running, or a tunnel running without smart-routing — e.g. a plain relay/proxy
 * path has no router). */
int32_t spark_set_routing_mode(const char *mode);

#ifdef __cplusplus
}
#endif

#endif /* SPARK_H */
