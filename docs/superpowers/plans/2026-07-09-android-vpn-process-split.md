# Android `:vpn` Process Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run `SparkVpnService` (and the Rust core it hosts) in a private `:vpn` process so the main-process Tauri WebView (~50 MB + ~24 GPU threads) can be reclaimed while the lean core keeps the tunnel alive.

**Architecture:** Add `android:process=":vpn"` to the service; replace the four direct `SparkBridge` JNI calls the main-process Tauri plugin makes (`servers`, `selectServer`, `setSplitTunnel`, `setRoutingMode`) and the `SparkState` reads with a `Messenger` control channel. The service exposes a control `Messenger` via `onBind` (delegating to `super.onBind` for the VPN framework); the plugin binds a `SparkControlClient` that does request/reply for servers/selectServer, one-way sends for the live setters, and receives pushed state into a main-process `SparkState` mirror. Packets never cross the boundary — only the control plane does.

**Tech Stack:** Kotlin (Android, minSdk 21, Kotlin 1.8.20, AGP 8.0.2), `Messenger`/`Handler`/`HandlerThread`, `kotlinx.coroutines` (`CompletableDeferred`, `withTimeoutOrNull`), JUnit 4 host unit tests, `cargo-ndk` for the native `.so`. Spec: `docs/superpowers/specs/2026-07-09-android-vpn-process-split-design.md`.

---

## Conventions used throughout

- **Android module dir:** `gui-tauri/tauri-plugin-spark-vpn/android` (namespace `org.getlantern.spark.vpn`; JNI package `org.getlantern.spark`).
- **Gradle host runner:** the Tauri-generated project at `gui-tauri/src-tauri/gen/android` (has `gradlew`) includes the plugin as `:tauri-plugin-spark-vpn`. Run gradle from there.
- **Fast unit tests (no Rust build):** `./gradlew :tauri-plugin-spark-vpn:testDebugUnitTest -x cargoNdkBuild`. The pure classes never load the native lib, so excluding `cargoNdkBuild` is safe and skips the multi-minute NDK build. (Kotlin still compiles against the Android `android.jar` stubs.)
- **Kotlin 1.8.20 caveat:** `enum.entries` is NOT available (that's 1.9+). Use `values()`.
- **New pure-Kotlin package:** `org.getlantern.spark.control` under `.../android/src/main/java/org/getlantern/spark/control/`.
- **New test package:** `.../android/src/test/java/org/getlantern/spark/control/` (the module has no `src/test` yet — create it).

## File structure

**Create:**
- `.../src/main/java/org/getlantern/spark/control/ControlProtocol.kt` — message codes, bundle keys, `VpnState`↔wire mapper (pure Kotlin).
- `.../src/main/java/org/getlantern/spark/control/PendingRequests.kt` — thread-safe request-id→`CompletableDeferred` correlation registry (pure Kotlin).
- `.../src/main/java/org/getlantern/spark/SparkControlClient.kt` — main-process IPC client (Android glue).
- `.../src/test/java/org/getlantern/spark/control/ControlProtocolTest.kt`
- `.../src/test/java/org/getlantern/spark/control/PendingRequestsTest.kt`
- `.../src/test/java/org/getlantern/spark/SparkStateTest.kt`

**Modify:**
- `.../src/main/java/org/getlantern/spark/SparkState.kt` — add `onChange` hook.
- `.../src/main/java/org/getlantern/spark/SparkVpnService.kt` — control `Messenger`, `onBind` dispatch, `handleControl`, `sendState`, `onCreate`/`onDestroy` wiring, `ACTION_CONTROL`.
- `.../src/main/java/org/getlantern/spark/vpn/SparkVpnPlugin.kt` — route the four commands through `SparkControlClient`; bind at init; remove all `SparkBridge` references.
- `.../src/main/AndroidManifest.xml` — add `android:process=":vpn"`.

**Unchanged (verify only):** `SparkBridge.kt` (now `:vpn`-only), `VpnController.kt`, all Rust (`mobile.rs`/`commands.rs`), the SvelteKit UI.

---

## Task 1: Control protocol + state mapper (pure Kotlin, TDD)

**Files:**
- Create: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/control/ControlProtocol.kt`
- Test: `gui-tauri/tauri-plugin-spark-vpn/android/src/test/java/org/getlantern/spark/control/ControlProtocolTest.kt`

- [ ] **Step 1: Write the failing test**

Create `.../src/test/java/org/getlantern/spark/control/ControlProtocolTest.kt`:

```kotlin
package org.getlantern.spark.control

import org.getlantern.spark.VpnState
import org.junit.Assert.assertEquals
import org.junit.Test

class ControlProtocolTest {
    @Test
    fun stateRoundTripsThroughWire() {
        for (s in VpnState.values()) {
            assertEquals(s, vpnStateFromWire(s.toWire()))
        }
    }

    @Test
    fun unknownWireValueDecodesToDisconnected() {
        assertEquals(VpnState.DISCONNECTED, vpnStateFromWire(999))
    }

    @Test
    fun negativeWireValueDecodesToDisconnected() {
        assertEquals(VpnState.DISCONNECTED, vpnStateFromWire(-1))
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:testDebugUnitTest -x cargoNdkBuild --tests "org.getlantern.spark.control.ControlProtocolTest"`
Expected: FAIL — compilation error, `unresolved reference: toWire` / `vpnStateFromWire`.

- [ ] **Step 3: Write minimal implementation**

Create `.../src/main/java/org/getlantern/spark/control/ControlProtocol.kt`:

```kotlin
package org.getlantern.spark.control

import org.getlantern.spark.VpnState

/**
 * Wire contract for the `:vpn` control Messenger. Pure Kotlin (no Android types) so the encoding
 * and the [VpnState] mapping are host-unit-testable. `what` codes are split into a client→service
 * range and a service→client range so a stray cross-delivery can't be misread.
 */
object ControlMsg {
    // client -> service
    const val REGISTER = 1 // msg.replyTo = the client Messenger; service replies with current STATE
    const val UNREGISTER = 2
    const val GET_SERVERS = 3 // msg.arg1 = requestId
    const val SELECT_SERVER = 4 // msg.arg1 = requestId; data[INDEX] = Int
    const val SET_SPLIT_TUNNEL = 5 // data[JSON] = String (one-way, no reply)
    const val SET_ROUTING_MODE = 6 // data[MODE] = String (one-way, no reply)

    // service -> client
    const val STATE = 100 // msg.arg1 = VpnState wire ordinal
    const val SERVERS_REPLY = 101 // msg.arg1 = requestId; data[JSON] = String
    const val SELECT_SERVER_REPLY = 102 // msg.arg1 = requestId; data[OK] = Boolean
}

/** Keys for the [android.os.Bundle] payloads carried on control messages. */
object ControlKey {
    const val INDEX = "index"
    const val JSON = "json"
    const val MODE = "mode"
    const val OK = "ok"
}

/** Encode a [VpnState] for the wire as its enum ordinal. */
fun VpnState.toWire(): Int = ordinal

/**
 * Decode a wire ordinal back to a [VpnState]; any out-of-range value (a version skew or a corrupt
 * message) decodes to [VpnState.DISCONNECTED] rather than throwing. Uses `values()` (not `.entries`,
 * which needs Kotlin 1.9+).
 */
fun vpnStateFromWire(value: Int): VpnState =
    VpnState.values().getOrElse(value) { VpnState.DISCONNECTED }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:testDebugUnitTest -x cargoNdkBuild --tests "org.getlantern.spark.control.ControlProtocolTest"`
Expected: PASS (`BUILD SUCCESSFUL`, 3 tests).

- [ ] **Step 5: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/control/ControlProtocol.kt \
        gui-tauri/tauri-plugin-spark-vpn/android/src/test/java/org/getlantern/spark/control/ControlProtocolTest.kt
git commit -m "feat(android): control-plane wire protocol + VpnState mapper"
```

---

## Task 2: PendingRequests correlation registry (pure Kotlin, TDD)

**Files:**
- Create: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/control/PendingRequests.kt`
- Test: `gui-tauri/tauri-plugin-spark-vpn/android/src/test/java/org/getlantern/spark/control/PendingRequestsTest.kt`

- [ ] **Step 1: Write the failing test**

Create `.../src/test/java/org/getlantern/spark/control/PendingRequestsTest.kt`:

```kotlin
package org.getlantern.spark.control

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PendingRequestsTest {
    @Test
    fun createReturnsMonotonicIds() {
        val r = PendingRequests<String>()
        assertEquals(1, r.create(CompletableDeferred()))
        assertEquals(2, r.create(CompletableDeferred()))
    }

    @Test
    fun resolveCompletesTheMatchingDeferred() = runBlocking {
        val r = PendingRequests<String>()
        val d = CompletableDeferred<String>()
        val id = r.create(d)
        assertTrue(r.resolve(id, "hello"))
        assertEquals("hello", d.await())
        assertEquals(0, r.size)
    }

    @Test
    fun resolveUnknownIdIsNoop() {
        val r = PendingRequests<String>()
        assertFalse(r.resolve(999, "x"))
    }

    @Test
    fun resolveTwiceOnlyCompletesOnce() {
        val r = PendingRequests<String>()
        val id = r.create(CompletableDeferred())
        assertTrue(r.resolve(id, "a"))
        assertFalse(r.resolve(id, "b"))
    }

    @Test
    fun failAllCompletesEveryInFlightWithFallback() = runBlocking {
        val r = PendingRequests<String>()
        val d1 = CompletableDeferred<String>()
        val d2 = CompletableDeferred<String>()
        r.create(d1)
        r.create(d2)
        r.failAll("[]")
        assertEquals("[]", d1.await())
        assertEquals("[]", d2.await())
        assertEquals(0, r.size)
    }

    @Test
    fun removeDropsWithoutCompleting() {
        val r = PendingRequests<String>()
        val d = CompletableDeferred<String>()
        val id = r.create(d)
        r.remove(id)
        assertFalse(d.isCompleted)
        assertFalse(r.resolve(id, "x"))
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:testDebugUnitTest -x cargoNdkBuild --tests "org.getlantern.spark.control.PendingRequestsTest"`
Expected: FAIL — `unresolved reference: PendingRequests`.

- [ ] **Step 3: Write minimal implementation**

Create `.../src/main/java/org/getlantern/spark/control/PendingRequests.kt`:

```kotlin
package org.getlantern.spark.control

import kotlinx.coroutines.CompletableDeferred

/**
 * Correlates outbound control requests with their replies by a monotonic request id. `create` runs
 * on the caller's coroutine dispatcher while `resolve` runs on the incoming-Messenger handler
 * thread, so the map is guarded by a lock. Pure Kotlin (no Android types) → host-unit-testable.
 *
 * [T] is the reply payload type (String for the servers JSON, Boolean for the select-server ok),
 * so a client keeps one registry per reply type and each reply routes to the right one by `what`.
 */
class PendingRequests<T> {
    private val lock = Any()
    private var nextId = 1
    private val pending = HashMap<Int, CompletableDeferred<T>>()

    /** Register [deferred] under a fresh id and return that id to stamp on the outbound message. */
    fun create(deferred: CompletableDeferred<T>): Int = synchronized(lock) {
        val id = nextId++
        pending[id] = deferred
        id
    }

    /** Complete the deferred registered under [id] with [value]. Returns false if [id] is unknown
     *  (a late/duplicate reply) or was already completed. */
    fun resolve(id: Int, value: T): Boolean {
        val d = synchronized(lock) { pending.remove(id) } ?: return false
        return d.complete(value)
    }

    /** Drop the request under [id] without completing it (e.g. on the caller's own timeout). */
    fun remove(id: Int) {
        synchronized(lock) { pending.remove(id) }
    }

    /** Complete every in-flight request with [fallback] and clear the map (e.g. on disconnect). */
    fun failAll(fallback: T) {
        val snapshot = synchronized(lock) {
            val s = pending.values.toList()
            pending.clear()
            s
        }
        snapshot.forEach { it.complete(fallback) }
    }

    /** Count of in-flight requests (for tests/diagnostics). */
    val size: Int get() = synchronized(lock) { pending.size }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:testDebugUnitTest -x cargoNdkBuild --tests "org.getlantern.spark.control.PendingRequestsTest"`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/control/PendingRequests.kt \
        gui-tauri/tauri-plugin-spark-vpn/android/src/test/java/org/getlantern/spark/control/PendingRequestsTest.kt
git commit -m "feat(android): thread-safe control-request correlation registry"
```

---

## Task 3: SparkState `onChange` hook (pure Kotlin, TDD)

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/VpnState.kt`
- Test: `gui-tauri/tauri-plugin-spark-vpn/android/src/test/java/org/getlantern/spark/SparkStateTest.kt`

- [ ] **Step 1: Write the failing test**

Create `.../src/test/java/org/getlantern/spark/SparkStateTest.kt`:

```kotlin
package org.getlantern.spark

import org.junit.Assert.assertEquals
import org.junit.Test

class SparkStateTest {
    @Test
    fun onChangeFiresWithEachNewValue() {
        val seen = mutableListOf<VpnState>()
        SparkState.onChange = { seen.add(it) }
        try {
            SparkState.set(VpnState.CONNECTING)
            SparkState.set(VpnState.CONNECTED)
        } finally {
            SparkState.onChange = null
            SparkState.set(VpnState.DISCONNECTED) // reset the global singleton for other tests
        }
        assertEquals(listOf(VpnState.CONNECTING, VpnState.CONNECTED), seen)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:testDebugUnitTest -x cargoNdkBuild --tests "org.getlantern.spark.SparkStateTest"`
Expected: FAIL — `unresolved reference: onChange`.

- [ ] **Step 3: Write minimal implementation**

Replace the body of `SparkState` in `.../src/main/java/org/getlantern/spark/VpnState.kt` with:

```kotlin
/** Process-global tunnel state. Each process holds its own singleton: in `:vpn` the service is the
 *  writer and wires [onChange] to its control broadcaster; in the UI process SparkControlClient is
 *  the writer, feeding it from pushed control messages (the plugin also sets CONNECTING optimistically
 *  at connect start). The UI observes [state]. */
object SparkState {
    private val _state = MutableStateFlow(VpnState.DISCONNECTED)
    val state: StateFlow<VpnState> = _state.asStateFlow()

    /** Invoked after every [set] if non-null. In `:vpn` the service wires this to broadcast state to
     *  the bound UI client; null (unused) in the UI process. @Volatile since set() is called from
     *  several threads. */
    @Volatile
    var onChange: ((VpnState) -> Unit)? = null

    /** Publish a new tunnel state (and notify [onChange]). */
    fun set(value: VpnState) {
        _state.value = value
        onChange?.invoke(value)
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:testDebugUnitTest -x cargoNdkBuild --tests "org.getlantern.spark.SparkStateTest"`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/VpnState.kt \
        gui-tauri/tauri-plugin-spark-vpn/android/src/test/java/org/getlantern/spark/SparkStateTest.kt
git commit -m "feat(android): SparkState onChange hook for cross-process state broadcast"
```

---

## Task 4: Service-side control channel in `:vpn` (Android glue)

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/SparkVpnService.kt`

Not host-unit-testable (Messenger/Handler/onBind need a Looper and the VPN framework; no Robolectric). Gate: it compiles; behavior is validated on-device in Task 8.

- [ ] **Step 1: Add control imports**

In `SparkVpnService.kt`, add these imports (alongside the existing `android.os.*` imports):

```kotlin
import android.os.Bundle
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import org.getlantern.spark.control.ControlKey
import org.getlantern.spark.control.ControlMsg
import org.getlantern.spark.control.toWire
```

- [ ] **Step 2: Add control fields**

In the `SparkVpnService` class body, next to the other `private var` fields (after `tunnelGeneration`), add:

```kotlin
// Control-plane IPC (Messenger). The UI process (a different process after android:process=":vpn")
// binds here to drive servers/selectServer/split-tunnel/routing-mode and receive pushed state.
// Handled on a dedicated thread so control traffic never touches the main looper.
private var controlThread: HandlerThread? = null
private var controlMessenger: Messenger? = null

// The single registered UI client (last REGISTER wins — the UI is the only client). State pushes
// go here; cleared when a send fails (client process gone).
private var controlClient: Messenger? = null
```

- [ ] **Step 3: Wire onCreate / onDestroy and add onBind + handlers**

Add an `onCreate` override (the class has none today) and extend the existing `onDestroy`. Then add the control methods. Insert `onCreate` right before `onStartCommand`:

```kotlin
    override fun onCreate() {
        super.onCreate()
        // Broadcast every state transition to the bound UI client. Set here (before onStartCommand's
        // startTunnel) so the very first CONNECTING is broadcast too (a no-op until a client registers,
        // which then gets the current state on REGISTER).
        SparkState.onChange = { state -> sendState(state) }
    }
```

Replace the existing `onDestroy` with:

```kotlin
    override fun onDestroy() {
        stopTunnel()
        SparkState.onChange = null
        controlClient = null
        controlThread?.quitSafely()
        controlThread = null
        super.onDestroy()
    }
```

Add these methods (place them after `onDestroy`, before the `companion object`):

```kotlin
    /**
     * Lazily create the control [Messenger] backed by a dedicated [HandlerThread]. Returned from
     * [onBind] for the CONTROL action.
     */
    private fun controlMessenger(): Messenger {
        controlMessenger?.let { return it }
        val t = HandlerThread("spark-control").apply { start() }
        controlThread = t
        val m = Messenger(Handler(t.looper, Handler.Callback { msg -> handleControl(msg); true }))
        controlMessenger = m
        return m
    }

    /**
     * VpnService binds for two purposes now: the VPN framework (SERVICE_INTERFACE) and our control
     * channel (ACTION_CONTROL). Per the VpnService.onBind contract we MUST return super.onBind for
     * SERVICE_INTERFACE; for anything else return our control binder.
     */
    override fun onBind(intent: Intent?): IBinder? {
        if (intent?.action == SERVICE_INTERFACE) return super.onBind(intent)
        return controlMessenger().binder
    }

    /** Dispatch one inbound control message (on the control thread). */
    private fun handleControl(msg: Message) {
        when (msg.what) {
            ControlMsg.REGISTER -> {
                controlClient = msg.replyTo
                // Immediately sync current state so a late/rebinding UI (e.g. app reopened while the
                // tunnel kept running) is correct without waiting for the next transition.
                sendState(SparkState.state.value)
            }
            ControlMsg.UNREGISTER -> controlClient = null
            ControlMsg.GET_SERVERS -> {
                val json = runCatching { SparkBridge.nativeServers() }.getOrNull() ?: "[]"
                reply(msg.replyTo, ControlMsg.SERVERS_REPLY, msg.arg1,
                    Bundle().apply { putString(ControlKey.JSON, json) })
            }
            ControlMsg.SELECT_SERVER -> {
                val index = msg.data?.getInt(ControlKey.INDEX, -1) ?: -1
                val ok = runCatching { SparkBridge.nativeSelectServer(index) }.getOrDefault(false)
                reply(msg.replyTo, ControlMsg.SELECT_SERVER_REPLY, msg.arg1,
                    Bundle().apply { putBoolean(ControlKey.OK, ok) })
            }
            ControlMsg.SET_SPLIT_TUNNEL -> {
                val json = msg.data?.getString(ControlKey.JSON) ?: return
                runCatching { SparkBridge.nativeSetSplitTunnel(json) }
                    .onFailure { Log.w(TAG, "nativeSetSplitTunnel failed", it) }
            }
            ControlMsg.SET_ROUTING_MODE -> {
                val mode = msg.data?.getString(ControlKey.MODE) ?: return
                runCatching { SparkBridge.nativeSetRoutingMode(mode) }
                    .onFailure { Log.w(TAG, "nativeSetRoutingMode failed", it) }
            }
        }
    }

    /** Send a correlated reply ([requestId] echoed in arg1) back to the requester. */
    private fun reply(to: Messenger?, what: Int, requestId: Int, data: Bundle) {
        to ?: return
        val m = Message.obtain(null, what, requestId, 0).apply { this.data = data }
        runCatching { to.send(m) }.onFailure { Log.w(TAG, "control reply send failed", it) }
    }

    /** Push a state transition to the registered UI client; clear it if the send fails (gone). */
    private fun sendState(state: VpnState) {
        val c = controlClient ?: return
        val m = Message.obtain(null, ControlMsg.STATE, state.toWire(), 0)
        runCatching { c.send(m) }.onFailure { controlClient = null }
    }
```

- [ ] **Step 4: Add the ACTION_CONTROL constant**

In the `companion object`, add (next to `ACTION_STOP`/`ACTION_APPLY_APPS`):

```kotlin
        /** Explicit-intent action the UI process uses to bind the control Messenger (distinct from
         *  the VPN framework's SERVICE_INTERFACE bind). */
        const val ACTION_CONTROL = "org.getlantern.spark.CONTROL"
```

- [ ] **Step 5: Verify it compiles**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:compileDebugKotlin -x cargoNdkBuild`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 6: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/SparkVpnService.kt
git commit -m "feat(android): control Messenger + onBind dispatch + state broadcast in :vpn service"
```

---

## Task 5: SparkControlClient (main-process IPC client, Android glue)

**Files:**
- Create: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/SparkControlClient.kt`

Not host-unit-testable (bindService/Messenger). Its correlation + mapping internals ARE covered by Tasks 1–2. Gate: compiles; validated on-device in Task 8.

- [ ] **Step 1: Write the client**

Create `.../src/main/java/org/getlantern/spark/SparkControlClient.kt`:

```kotlin
package org.getlantern.spark

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import org.getlantern.spark.control.ControlKey
import org.getlantern.spark.control.ControlMsg
import org.getlantern.spark.control.PendingRequests
import org.getlantern.spark.control.vpnStateFromWire

/**
 * Main-process client for the `:vpn` control Messenger. Binds to [SparkVpnService] (ACTION_CONTROL),
 * registers a reply channel, mirrors pushed state into the main-process [SparkState], and does
 * request/reply for servers/selectServer plus one-way sends for the live setters.
 *
 * Lifecycle: adopt-bind at plugin init (flags=0 → no-op if the tunnel isn't running, so it never
 * spawns an idle `:vpn`); auto-create bind on connect (the service is being started anyway);
 * unbind when a terminal-down state (DISCONNECTED/FAILED) is observed or the connection dies, so a
 * lingering binding never keeps a stopped `:vpn` alive.
 */
class SparkControlClient(private val context: Context) {
    private val incomingThread = HandlerThread("spark-control-client").apply { start() }
    private val incoming = Messenger(
        Handler(incomingThread.looper, Handler.Callback { msg -> handleReply(msg); true }),
    )

    private val serversPending = PendingRequests<String>()
    private val selectPending = PendingRequests<Boolean>()

    @Volatile private var service: Messenger? = null
    @Volatile private var bound = false

    private val conn = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
            val svc = Messenger(binder)
            service = svc
            val m = Message.obtain(null, ControlMsg.REGISTER).apply { replyTo = incoming }
            runCatching { svc.send(m) }.onFailure { Log.w(TAG, "REGISTER send failed", it) }
        }

        override fun onServiceDisconnected(name: ComponentName?) = onLost()
        override fun onBindingDied(name: ComponentName?) = onLost()
    }

    private fun onLost() {
        service = null
        // Fail in-flight requests to their lenient defaults so callers don't hang.
        serversPending.failAll("[]")
        selectPending.failAll(false)
        unbind()
    }

    /** Adopt an already-running `:vpn` if present; no-op (and no process spawn) otherwise. */
    fun bindIfRunning() = bind(autoCreate = false)

    /** Ensure bound during a connect (the foreground service is being started concurrently). */
    fun bindForConnect() = bind(autoCreate = true)

    private fun bind(autoCreate: Boolean) {
        if (bound) return
        val intent = Intent(context, SparkVpnService::class.java).setAction(SparkVpnService.ACTION_CONTROL)
        val flags = if (autoCreate) Context.BIND_AUTO_CREATE else 0
        val ok = runCatching { context.bindService(intent, conn, flags) }.getOrDefault(false)
        if (ok) {
            bound = true
        } else {
            // bindService records the ServiceConnection even when it returns false (service not
            // running); release it so a later bind() starts clean.
            runCatching { context.unbindService(conn) }
        }
    }

    private fun unbind() {
        if (!bound) return
        bound = false
        service = null
        runCatching { context.unbindService(conn) }
    }

    private fun handleReply(msg: Message) {
        when (msg.what) {
            ControlMsg.STATE -> {
                val s = vpnStateFromWire(msg.arg1)
                SparkState.set(s)
                if (s == VpnState.DISCONNECTED || s == VpnState.FAILED) unbind()
            }
            ControlMsg.SERVERS_REPLY -> {
                val json = msg.data?.getString(ControlKey.JSON) ?: "[]"
                serversPending.resolve(msg.arg1, json)
            }
            ControlMsg.SELECT_SERVER_REPLY -> {
                val ok = msg.data?.getBoolean(ControlKey.OK, false) ?: false
                selectPending.resolve(msg.arg1, ok)
            }
        }
    }

    /** The live server pool as a JSON array string; "[]" if unbound or the request times out. */
    suspend fun getServers(): String {
        val svc = service ?: return "[]"
        val deferred = CompletableDeferred<String>()
        val id = serversPending.create(deferred)
        val m = Message.obtain(null, ControlMsg.GET_SERVERS, id, 0).apply { replyTo = incoming }
        if (runCatching { svc.send(m) }.isFailure) {
            serversPending.remove(id)
            return "[]"
        }
        return withTimeoutOrNull(REQUEST_TIMEOUT_MS) { deferred.await() }
            ?: run { serversPending.remove(id); "[]" }
    }

    /** Pin which pool member new flows dial; false if unbound or the request times out. */
    suspend fun selectServer(index: Int): Boolean {
        val svc = service ?: return false
        val deferred = CompletableDeferred<Boolean>()
        val id = selectPending.create(deferred)
        val m = Message.obtain(null, ControlMsg.SELECT_SERVER, id, 0).apply {
            replyTo = incoming
            data = Bundle().apply { putInt(ControlKey.INDEX, index) }
        }
        if (runCatching { svc.send(m) }.isFailure) {
            selectPending.remove(id)
            return false
        }
        return withTimeoutOrNull(REQUEST_TIMEOUT_MS) { deferred.await() }
            ?: run { selectPending.remove(id); false }
    }

    /** One-way live push of the split-tunnel bypass list (dropped if unbound; the persisted file
     *  still applies on the next start). */
    fun setSplitTunnel(json: String) {
        val svc = service ?: return
        val m = Message.obtain(null, ControlMsg.SET_SPLIT_TUNNEL).apply {
            data = Bundle().apply { putString(ControlKey.JSON, json) }
        }
        runCatching { svc.send(m) }
    }

    /** One-way live push of the routing mode (dropped if unbound; persisted file applies on start). */
    fun setRoutingMode(mode: String) {
        val svc = service ?: return
        val m = Message.obtain(null, ControlMsg.SET_ROUTING_MODE).apply {
            data = Bundle().apply { putString(ControlKey.MODE, mode) }
        }
        runCatching { svc.send(m) }
    }

    companion object {
        private const val TAG = "SparkControlClient"
        private const val REQUEST_TIMEOUT_MS = 5_000L
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:compileDebugKotlin -x cargoNdkBuild`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/SparkControlClient.kt
git commit -m "feat(android): SparkControlClient — main-process Messenger client for :vpn core"
```

---

## Task 6: Route the plugin through SparkControlClient; remove SparkBridge refs

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/vpn/SparkVpnPlugin.kt`

- [ ] **Step 1: Swap the SparkBridge import for the control client**

In `SparkVpnPlugin.kt`, delete the import line `import org.getlantern.spark.SparkBridge` and add:

```kotlin
import org.getlantern.spark.SparkControlClient
```

(Keep the existing `SparkState`, `VpnController`, `VpnState` imports.)

- [ ] **Step 2: Construct + adopt-bind the client in the plugin**

In the class body, add a field next to `scope`/`connecting` and adopt-bind in `init`. Change:

```kotlin
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    @Volatile private var connecting = false

    init {
```

to:

```kotlin
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Control channel to the core in the :vpn process. Adopt-bind now so a tunnel already running
    // from a prior UI-process death re-syncs its state; connect() upgrades to an auto-create bind.
    private val control = SparkControlClient(activity)

    @Volatile private var connecting = false

    init {
        control.bindIfRunning()
```

- [ ] **Step 3: Bind for connect in startAndAwaitReady**

In `startAndAwaitReady`, add the bind right after `VpnController.start(activity)`:

```kotlin
    private fun startAndAwaitReady(invoke: Invoke) {
        SparkState.set(VpnState.CONNECTING)
        VpnController.start(activity)
        control.bindForConnect()
        scope.launch {
```

- [ ] **Step 4: Route `servers` through the control client**

Replace the whole `servers` @Command with:

```kotlin
    @Command
    fun servers(invoke: Invoke) {
        scope.launch {
            val json = runCatching { control.getServers() }.getOrDefault("[]")
            val ret = JSObject()
            ret.put("value", json)
            invoke.resolve(ret)
        }
    }
```

- [ ] **Step 5: Route `selectServer` through the control client**

Replace the whole `selectServer` @Command with:

```kotlin
    @Command
    fun selectServer(invoke: Invoke) {
        val args = invoke.parseArgs(SelectServerArgs::class.java)
        scope.launch {
            val ok = runCatching { control.selectServer(args.index) }.getOrDefault(false)
            val ret = JSObject()
            ret.put("ok", ok)
            invoke.resolve(ret)
        }
    }
```

- [ ] **Step 6: Route the live setters through the control client**

In `setSplitTunnel`, replace the live-push block:

```kotlin
        if (SparkState.state.value == VpnState.CONNECTED) {
            runCatching { SparkBridge.nativeSetSplitTunnel(canonical) }
                .onFailure { Log.w(TAG, "nativeSetSplitTunnel failed", it) }
        }
```

with:

```kotlin
        if (SparkState.state.value == VpnState.CONNECTED) {
            runCatching { control.setSplitTunnel(canonical) }
                .onFailure { Log.w(TAG, "setSplitTunnel push failed", it) }
        }
```

In `setRoutingMode`, replace the live-push block:

```kotlin
        if (SparkState.state.value == VpnState.CONNECTED) {
            runCatching { SparkBridge.nativeSetRoutingMode(mode) }
                .onFailure { Log.w(TAG, "nativeSetRoutingMode failed", it) }
        }
```

with:

```kotlin
        if (SparkState.state.value == VpnState.CONNECTED) {
            runCatching { control.setRoutingMode(mode) }
                .onFailure { Log.w(TAG, "setRoutingMode push failed", it) }
        }
```

- [ ] **Step 7: Verify no SparkBridge references remain in the main-process plugin**

Run: `grep -rn "SparkBridge" gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/vpn/`
Expected: **no output** (empty). If any line prints, the split is incomplete — the native lib would load in the main process.

- [ ] **Step 8: Verify it compiles**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:compileDebugKotlin -x cargoNdkBuild`
Expected: `BUILD SUCCESSFUL`.

- [ ] **Step 9: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/java/org/getlantern/spark/vpn/SparkVpnPlugin.kt
git commit -m "feat(android): plugin drives core via SparkControlClient; drop direct JNI in UI process"
```

---

## Task 7: Move the service to the `:vpn` process

**Files:**
- Modify: `gui-tauri/tauri-plugin-spark-vpn/android/src/main/AndroidManifest.xml`

- [ ] **Step 1: Add the process attribute**

In `AndroidManifest.xml`, change the `<service>` opening tag from:

```xml
        <service
            android:name="org.getlantern.spark.SparkVpnService"
            android:exported="false"
            android:foregroundServiceType="specialUse"
            android:permission="android.permission.BIND_VPN_SERVICE">
```

to (add the `android:process` line and update the comment above the element):

```xml
        <service
            android:name="org.getlantern.spark.SparkVpnService"
            android:exported="false"
            android:foregroundServiceType="specialUse"
            android:process=":vpn"
            android:permission="android.permission.BIND_VPN_SERVICE">
```

Also update the comment block directly above the `<service>` to note the process split. Change the sentence "This manifest merges into the consuming app." to:

```xml
             the app is backgrounded. It runs in a private ":vpn" process (android:process) so the
             UI process's WebView can be reclaimed while the tunnel stays up; the UI drives it over a
             control Messenger (SparkControlClient). This manifest merges into the consuming app. -->
```

- [ ] **Step 2: Verify the manifest merges and the module assembles**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:assembleDebug`
Expected: `BUILD SUCCESSFUL` (this DOES build the `.so` via cargoNdkBuild — requires the Android NDK; first run is slow). The merged manifest should carry `android:process=":vpn"` on the service.

- [ ] **Step 3: Commit**

```bash
git add gui-tauri/tauri-plugin-spark-vpn/android/src/main/AndroidManifest.xml
git commit -m "feat(android): run SparkVpnService in a private :vpn process"
```

---

## Task 8: Full gate, Android build, on-device validation + memory measurement

**Files:** none (verification only). This is the acceptance evidence per the spec.

- [ ] **Step 1: Kotlin host unit tests (all three pure suites)**

Run: `cd gui-tauri/src-tauri/gen/android && ./gradlew :tauri-plugin-spark-vpn:testDebugUnitTest -x cargoNdkBuild`
Expected: `BUILD SUCCESSFUL` — 10 tests (3 + 6 + 1).

- [ ] **Step 2: Rust sanity gates (unchanged crates must stay green)**

The plugin Rust crate and core have no changes; confirm nothing regressed:

```bash
cd gui-tauri/tauri-plugin-spark-vpn && cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test
```
Expected: all green.

- [ ] **Step 3: Android JNI clippy for the native crate**

Run: `cargo ndk -t arm64-v8a clippy -p spark-android -- -D warnings`
Expected: green (per the `spark-android-target-verify` convention — plain `--target aarch64-linux-android` fails on NDK clang; `cargo ndk` is the correct driver).

- [ ] **Step 4: Build + install the app on the Redmi**

Confirm the device: `adb devices` (expect `HQAEJJWG6HYDWW9P device`). Build and install the Tauri Android app (arm64):

```bash
cd gui-tauri && npm run tauri android build -- --apk --target aarch64
adb install -r src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk
```
(If the release APK path differs, locate it: `find src-tauri/gen/android/app/build/outputs/apk -name '*.apk'`. A debug build — `npm run tauri android dev` or `assembleDebug` + install — is acceptable for validation.)

- [ ] **Step 5: Capture the BEFORE memory baseline (single-process, pre-split) — optional if not already captured**

If a pre-split baseline wasn't recorded, check out `origin/main`, build/install, connect, background, and record `adb shell dumpsys meminfo org.getlantern.spark` (note the main-process PSS backgrounded-while-connected). Then return to this branch. (The prior profiling already captured ~63–121 MB PSS whole-process; that is an acceptable baseline to cite.)

- [ ] **Step 6: Functional validation across the process boundary**

Grant VPN consent and connect from the UI. Verify every command still works now that the core is in `:vpn`:
1. **status** — UI shows Connecting → Connected.
2. **servers** — the server list populates (`servers` round-trips over Messenger).
3. **selectServer** — pinning a server takes effect.
4. **setSplitTunnel** (websites) — toggle a live change; confirm applied.
5. **setRoutingMode** — switch smart/full live; confirm applied.
6. **setExcludedApps** (apps) — toggle an app; confirm the tunnel rebuilds (ACTION_APPLY_APPS).

Confirm two processes exist while connected: `adb shell ps -A | grep org.getlantern.spark` — expect both `org.getlantern.spark` and `org.getlantern.spark:vpn`.

- [ ] **Step 7: Verify the tunnel survives UI-process death (the core win)**

With the tunnel connected and traffic flowing (e.g. a YouTube stream):
1. Background the app (Home button).
2. Confirm the `:vpn` process is still alive and streaming continues: `adb shell ps -A | grep spark:vpn` (present), and traffic keeps flowing.
3. Force the main (UI) process to be reclaimed — either via memory pressure or explicitly:
   `adb shell am kill org.getlantern.spark` (kills background processes of the package's main process; the foreground `:vpn` service is protected and should NOT die).
4. Confirm `:vpn` survives and the stream continues.
5. Reopen the app; confirm the UI re-syncs to **Connected** (via the REGISTER state snapshot) without a reconnect.

- [ ] **Step 8: Capture the AFTER memory measurement (the documented win)**

With the tunnel connected and the app backgrounded, record the main-process footprint:

```bash
adb shell dumpsys meminfo org.getlantern.spark   # main/UI process — should be reclaimable / lower
adb shell dumpsys meminfo org.getlantern.spark:vpn  # the lean core process
```
Save both to `docs/android-vpn-process-split-measurement.md` alongside the pre-split baseline, showing the WebView memory is now isolated to (and reclaimable from) the UI process while `:vpn` stays small.

- [ ] **Step 9: Restore device state**

`adb shell dumpsys battery reset` (undo any masked charging state used during measurement).

- [ ] **Step 10: Commit the measurement doc**

```bash
git add docs/android-vpn-process-split-measurement.md
git commit -m "docs(android): before/after memory measurement for the :vpn process split"
```

- [ ] **Step 11: Open the PR**

```bash
git push -u origin fisk/android-vpn-process-split
gh pr create --title "Android: run the VPN service + core in a private :vpn process" --body "<summary + the mermaid control-flow sequence diagram + on-device results + note that Messenger/onBind/bindService glue is validated on-device, not host-unit-tested>"
```
Include a mermaid `sequenceDiagram` of the connect + state-push + servers round-trip across the UI↔`:vpn` boundary (per the repo PR convention for cross-layer changes), and flag that the IPC glue is on-device-validated.

---

## Self-review notes (author)

- **Spec coverage:** manifest process split (Task 7); Messenger control channel + onBind (Task 4); SparkControlClient with the four commands + state mirror (Tasks 5–6); SparkBridge-only-in-`:vpn` invariant (Task 6 Step 7 grep gate); one-way setters / request-reply / push mapping (Tasks 1, 4, 5); lenient unbound/timeout defaults (Task 5); bind-flag lifecycle (Task 5 + Task 6); pure-Kotlin unit tests (Tasks 1–3); compile gates + on-device validation + before/after meminfo (Task 8). All spec sections map to a task.
- **Type consistency:** `toWire()`/`vpnStateFromWire()`, `ControlMsg.*`, `ControlKey.*`, `PendingRequests<T>` (`create`/`resolve`/`remove`/`failAll`/`size`), `SparkControlClient` (`bindIfRunning`/`bindForConnect`/`getServers`/`selectServer`/`setSplitTunnel`/`setRoutingMode`), `SparkState.onChange`, `SparkVpnService.ACTION_CONTROL` — names are identical across every task that references them.
- **No Rust changes:** `@Command` names/arg-shapes/return-shapes are unchanged, so `mobile.rs`/`commands.rs` and the SvelteKit backend seam need no edits.
