package org.getlantern.spark.ui

import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import androidx.compose.runtime.LaunchedEffect
import org.getlantern.spark.ServerInfo
import org.getlantern.spark.parseServers
import org.getlantern.spark.SparkBridge
import org.getlantern.spark.SparkState
import org.getlantern.spark.VpnController
import org.getlantern.spark.VpnState
import org.getlantern.spark.Selection
import android.app.Activity
import androidx.compose.ui.res.stringResource
import org.getlantern.spark.R

@Composable
fun HomeScreen(onOpenServers: () -> Unit) {
    val context = LocalContext.current
    val state by SparkState.state.collectAsStateWithLifecycle()
    val selectedIdx by Selection.index.collectAsStateWithLifecycle()

    val lifecycleOwner = LocalLifecycleOwner.current
    var servers by remember { mutableStateOf<List<ServerInfo>>(emptyList()) }
    // Poll the live pool only while the UI is at least STARTED — pauses in the background.
    LaunchedEffect(lifecycleOwner) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                servers = withContext(Dispatchers.IO) { parseServers(SparkBridge.nativeServers()) }
                delay(2000)
            }
        }
    }
    // Prefer the pinned member (Selection.index) over the auto-best (isCurrent) so the card
    // matches the "Selected location" label immediately after a pin, before the next poll.
    val current = selectedIdx?.let { idx -> servers.firstOrNull { it.index == idx } }
        ?: servers.firstOrNull { it.isCurrent }

    val connected = state == VpnState.CONNECTED
    val connecting = state == VpnState.CONNECTING

    // VPN consent flow: on RESULT_OK start the service. (consentIntent==null => already granted.)
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) VpnController.start(context)
    }

    fun toggle() {
        if (connecting) return
        if (connected) {
            VpnController.stop(context)
        } else {
            val intent = VpnController.consentIntent(context)
            if (intent != null) launcher.launch(intent) else VpnController.start(context)
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(SparkColors.bg),
    ) {
        AppBar()
        Column(
            Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
        ) {
            // Hero: the toggle, vertically centered above the card.
            Box(
                Modifier
                    .fillMaxWidth()
                    .weight(1f),
                contentAlignment = Alignment.Center,
            ) {
                VpnSwitch(on = connected, busy = connecting, onToggle = ::toggle)
            }
            StatusCard(
                state = state,
                current = current,
                autoSelected = selectedIdx == null,
                onOpenServers = onOpenServers,
            )
            Spacer(Modifier.height(10.dp))
        }
    }
}

@Composable
private fun AppBar() {
    Row(
        Modifier
            .fillMaxWidth()
            .height(56.dp)
            .shadow(elevation = 4.dp, clip = false)
            .background(SparkColors.bg)
            .padding(horizontal = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Box(Modifier.size(40.dp), contentAlignment = Alignment.Center) {
            // Decorative for now (no menu/settings screen in this build) — null so TalkBack skips it.
            Icon(MenuIcon, contentDescription = null, tint = SparkColors.textTertiary, modifier = Modifier.size(22.dp))
        }
        Text(
            stringResource(R.string.app_name),
            fontFamily = Urbanist,
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            color = SparkColors.textPrimary,
        )
    }
}

// VPNSwitch — track 140x70, knob 60 (5dp inset), travel 70 right when on; brand when on,
// off-grey otherwise; spinner (44dp) in place of the knob while connecting/busy.
@Composable
private fun VpnSwitch(on: Boolean, busy: Boolean, onToggle: () -> Unit) {
    val vpnLabel = stringResource(R.string.vpn)
    val connectedLabel = stringResource(R.string.status_connected)
    val connectingLabel = stringResource(R.string.status_connecting)
    val disconnectedLabel = stringResource(R.string.status_disconnected)
    val connectLabel = stringResource(R.string.connect)
    val disconnectLabel = stringResource(R.string.disconnect)
    val knobOffset by animateDpAsState(
        targetValue = if (on) 70.dp else 0.dp,
        animationSpec = tween(durationMillis = 320),
        label = "knob",
    )
    Box(
        Modifier
            .width(140.dp)
            .height(70.dp)
            .clip(RoundedCornerShape(35.dp))
            .background(if (on) SparkColors.brand else SparkColors.off)
            .semantics {
                contentDescription = vpnLabel
                stateDescription = when {
                    busy -> connectingLabel
                    on -> connectedLabel
                    else -> disconnectedLabel
                }
            }
            .clickable(
                enabled = !busy,
                onClickLabel = if (on) disconnectLabel else connectLabel,
                role = Role.Switch,
            ) { onToggle() },
        contentAlignment = Alignment.CenterStart,
    ) {
        if (busy) {
            CircularProgressIndicator(
                modifier = Modifier
                    .offset(x = 13.dp)
                    .size(44.dp),
                color = SparkColors.knob,
                strokeWidth = 6.dp,
            )
        } else {
            Box(
                Modifier
                    .offset(x = 5.dp + knobOffset)
                    .size(60.dp)
                    .shadow(4.dp, CircleShape)
                    .background(SparkColors.knob, CircleShape),
            )
        }
    }
}

@Composable
private fun StatusCard(
    state: VpnState,
    current: ServerInfo?,
    autoSelected: Boolean,
    onOpenServers: () -> Unit,
) {
    val statusValue = when (state) {
        VpnState.CONNECTED -> stringResource(R.string.status_connected)
        VpnState.CONNECTING -> stringResource(R.string.status_connecting)
        VpnState.FAILED -> stringResource(R.string.status_failed)
        VpnState.DISCONNECTED -> stringResource(R.string.status_disconnected)
    }
    val dotColor = when (state) {
        VpnState.CONNECTED -> SparkColors.success
        VpnState.CONNECTING -> SparkColors.brand
        else -> SparkColors.indicatorOff
    }

    Column(
        Modifier
            .fillMaxWidth()
            .shadow(elevation = 16.dp, shape = RoundedCornerShape(16.dp), ambientColor = SparkColors.shadow, spotColor = SparkColors.shadow)
            .clip(RoundedCornerShape(16.dp))
            .background(SparkColors.surface),
    ) {
        // VPN status
        StatusRow(
            leading = { Icon(GlobeIcon, null, tint = SparkColors.textSecondary, modifier = Modifier.size(20.dp)) },
            label = stringResource(R.string.vpn_status),
            value = statusValue,
            valueColor = if (state == VpnState.CONNECTED) SparkColors.success else SparkColors.textPrimary,
            trailing = {
                Box(
                    Modifier
                        .size(10.dp)
                        .background(dotColor, CircleShape),
                )
            },
        )
        Divider()
        // Smart location -> servers
        StatusRow(
            modifier = Modifier.clickable { onOpenServers() },
            leading = {
                if (current != null) {
                    Text(flagEmoji(current.countryCode), fontSize = 18.sp)
                } else {
                    Icon(PinIcon, null, tint = SparkColors.textSecondary, modifier = Modifier.size(20.dp))
                }
            },
            label = if (autoSelected) stringResource(R.string.smart_location) else stringResource(R.string.selected_location),
            value = if (current != null) serverLabel(current, stringResource(R.string.server)) else stringResource(R.string.fastest_server),
            valueColor = SparkColors.textPrimary,
            subtitle = current?.latencyMs?.let { stringResource(R.string.ms_format, it) },
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (autoSelected) Text("⚡", color = SparkColors.bolt, fontSize = 16.sp)
                    Icon(ChevronIcon, null, tint = SparkColors.textTertiary, modifier = Modifier.size(20.dp))
                }
            },
        )
        Divider()
        // Routing (non-interactive)
        StatusRow(
            leading = { Icon(RouteIcon, null, tint = SparkColors.textSecondary, modifier = Modifier.size(20.dp)) },
            label = stringResource(R.string.routing),
            value = stringResource(R.string.full_tunnel),
            valueColor = SparkColors.textPrimary,
            trailing = {
                Icon(ChevronIcon, null, tint = SparkColors.textTertiary, modifier = Modifier.size(20.dp))
            },
        )
    }
}

@Composable
private fun StatusRow(
    modifier: Modifier = Modifier,
    leading: @Composable () -> Unit,
    label: String,
    value: String,
    valueColor: Color,
    subtitle: String? = null,
    trailing: @Composable () -> Unit,
) {
    Column(
        modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 10.dp),
    ) {
        // head: icon + label
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(Modifier.width(24.dp), contentAlignment = Alignment.Center) { leading() }
            Text(label, fontFamily = Urbanist, fontSize = 14.sp, color = SparkColors.textSecondary)
        }
        // body: value (indented to align under the label) + trailing
        Row(
            Modifier
                .fillMaxWidth()
                .padding(start = 32.dp, top = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                value,
                fontFamily = Urbanist,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                color = valueColor,
                modifier = Modifier.weight(1f),
            )
            trailing()
        }
        if (subtitle != null) {
            Text(
                subtitle,
                fontFamily = Urbanist,
                fontSize = 12.sp,
                color = SparkColors.textTertiary,
                modifier = Modifier.padding(start = 32.dp, top = 1.dp),
            )
        }
    }
}

@Composable
private fun Divider() {
    Box(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .height(1.dp)
            .background(SparkColors.border),
    )
}

// --- Vector icons mirroring the Tauri SVGs (stroke-based, 24x24 viewport). ---

// autoMirror flips direction-sensitive icons (chevrons) in RTL locales (fa); custom ImageVectors
// are NOT auto-mirrored by Compose otherwise.
private fun strokeVector(name: String, autoMirror: Boolean = false, build: ImageVector.Builder.() -> Unit): ImageVector =
    ImageVector.Builder(name = name, defaultWidth = 24.dp, defaultHeight = 24.dp, viewportWidth = 24f, viewportHeight = 24f, autoMirror = autoMirror)
        .apply(build).build()

private fun ImageVector.Builder.stroke(
    width: Float = 1.8f,
    pathBuilder: androidx.compose.ui.graphics.vector.PathBuilder.() -> Unit,
) = path(
    fill = null,
    stroke = SolidColor(Color.Black),
    strokeLineWidth = width,
    strokeLineCap = StrokeCap.Round,
    strokeLineJoin = StrokeJoin.Round,
    pathFillType = PathFillType.NonZero,
    pathBuilder = pathBuilder,
)

private val MenuIcon: ImageVector = strokeVector("Menu") {
    stroke(2f) { moveTo(3f, 6f); lineTo(21f, 6f) }
    stroke(2f) { moveTo(3f, 12f); lineTo(21f, 12f) }
    stroke(2f) { moveTo(3f, 18f); lineTo(21f, 18f) }
}

private val GlobeIcon: ImageVector = strokeVector("Globe") {
    // circle r=9
    stroke { moveTo(21f, 12f); arcToRelative(9f, 9f, 0f, true, true, -18f, 0f); arcToRelative(9f, 9f, 0f, true, true, 18f, 0f); close() }
    stroke { moveTo(3f, 12f); lineTo(21f, 12f) }
    stroke { moveTo(12f, 3f); curveToRelative(4.5f, 4.5f, 4.5f, 13.5f, 0f, 18f); curveToRelative(-4.5f, -4.5f, -4.5f, -13.5f, 0f, -18f); close() }
}

private val PinIcon: ImageVector = strokeVector("Pin") {
    stroke { moveTo(12f, 21f); curveTo(12f, 21f, 6f, 15.7f, 6f, 11f); arcToRelative(6f, 6f, 0f, false, true, 12f, 0f); curveToRelative(0f, 4.7f, -6f, 10f, -6f, 10f); close() }
    stroke { moveTo(14.2f, 11f); arcToRelative(2.2f, 2.2f, 0f, true, true, -4.4f, 0f); arcToRelative(2.2f, 2.2f, 0f, true, true, 4.4f, 0f); close() }
}

private val RouteIcon: ImageVector = strokeVector("Route") {
    // bottom-left node (6,19 r2.5)
    stroke { moveTo(8.5f, 19f); arcToRelative(2.5f, 2.5f, 0f, true, true, -5f, 0f); arcToRelative(2.5f, 2.5f, 0f, true, true, 5f, 0f); close() }
    // top-right node (18,5 r2.5)
    stroke { moveTo(20.5f, 5f); arcToRelative(2.5f, 2.5f, 0f, true, true, -5f, 0f); arcToRelative(2.5f, 2.5f, 0f, true, true, 5f, 0f); close() }
    // connecting S-curve
    stroke { moveTo(8.5f, 19f); lineTo(14f, 19f); arcToRelative(4f, 4f, 0f, false, false, 0f, -8f); lineTo(10f, 11f); arcToRelative(4f, 4f, 0f, false, true, 0f, -8f); lineTo(15.5f, 3f) }
}

private val ChevronIcon: ImageVector = strokeVector("Chevron", autoMirror = true) {
    stroke(2f) { moveTo(9f, 18f); lineTo(15f, 12f); lineTo(9f, 6f) }
}
