package org.getlantern.spark.ui

import androidx.compose.animation.core.animateFloatAsState
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
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.graphics.vector.path
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import androidx.compose.ui.res.stringResource
import org.getlantern.spark.R
import org.getlantern.spark.Selection
import org.getlantern.spark.ServerInfo
import org.getlantern.spark.SparkBridge
import org.getlantern.spark.parseServers

@Composable
fun ServersScreen(onBack: () -> Unit) {
    val selectedIdx by Selection.index.collectAsStateWithLifecycle()

    val lifecycleOwner = LocalLifecycleOwner.current
    var servers by remember { mutableStateOf<List<ServerInfo>>(emptyList()) }
    var loaded by remember { mutableStateOf(false) }

    // Poll the live pool only while the UI is at least STARTED — pauses in the background.
    LaunchedEffect(lifecycleOwner) {
        lifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
            while (true) {
                servers = withContext(Dispatchers.IO) { parseServers(SparkBridge.nativeServers()) }
                loaded = true
                delay(3000)
            }
        }
    }

    val current = servers.firstOrNull { it.isCurrent }

    // Group by country (or name, or "—"), alphabetical. Memoized on `servers` so expand/collapse
    // and selection changes don't recompute the grouping/sort.
    val groups = remember(servers) {
        servers
            .groupBy { it.country?.takeIf { c -> c.isNotBlank() } ?: (it.name?.takeIf { n -> n.isNotBlank() } ?: "—") }
            .entries
            .sortedBy { it.key }
    }

    // Track expanded state for multi-member country groups.
    val expandedGroups = remember { mutableStateMapOf<String, Boolean>() }

    // Pin [index] (or auto when null) and pop back. Reflect the choice in the shared UI state
    // immediately; the native pin is best-effort (it may be a no-op when not yet connected).
    fun choose(index: Int?) {
        // Selection.pin applies the native pin on a process-lived scope, so navigating back here
        // (which cancels this composition) can't cancel it before it lands.
        Selection.pin(index)
        onBack()
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(SparkColors.bg),
    ) {
        // Top app bar
        Row(
            Modifier
                .fillMaxWidth()
                .height(56.dp)
                .shadow(elevation = 4.dp, clip = false)
                .background(SparkColors.bg)
                .padding(horizontal = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .size(48.dp)
                    .clickable { onBack() },
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    BackChevronIcon,
                    contentDescription = stringResource(R.string.back),
                    tint = SparkColors.textPrimary,
                    modifier = Modifier.size(22.dp),
                )
            }
            Text(
                stringResource(R.string.server_selection),
                fontFamily = Urbanist,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = SparkColors.textPrimary,
                modifier = Modifier.padding(start = 4.dp),
            )
        }

        LazyColumn(
            Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
        ) {
            // Smart location section
            item {
                Spacer(Modifier.height(16.dp))
                Text(
                    stringResource(R.string.smart_location),
                    fontFamily = Urbanist,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = SparkColors.textSecondary,
                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 6.dp),
                )
                val isAuto = selectedIdx == null
                Row(
                    Modifier
                        .fillMaxWidth()
                        .shadow(
                            elevation = 16.dp,
                            shape = RoundedCornerShape(16.dp),
                            ambientColor = SparkColors.shadow,
                            spotColor = SparkColors.shadow,
                        )
                        .clip(RoundedCornerShape(16.dp))
                        .background(
                            if (isAuto) SparkColors.brand.copy(alpha = 0.08f) else SparkColors.surface,
                        )
                        .clickable { choose(null) }
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(if (current != null) flagEmoji(current.countryCode) else "🌐", fontSize = 21.sp)
                    Column(Modifier.weight(1f)) {
                        Text(
                            if (current != null) serverLabel(current) else stringResource(R.string.fastest_server),
                            fontFamily = Urbanist,
                            fontSize = 15.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = SparkColors.textPrimary,
                        )
                        val sub = if (current != null) protocolLabel(current.protocol) else ""
                        if (sub.isNotEmpty()) {
                            Text(
                                sub,
                                fontFamily = Urbanist,
                                fontSize = 12.sp,
                                color = SparkColors.textTertiary,
                            )
                        }
                    }
                    current?.latencyMs?.let { LatencyPill(it) }
                    Text(
                        "⚡",
                        fontSize = 18.sp,
                        color = SparkColors.bolt.copy(alpha = if (isAuto) 1f else 0.28f),
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    stringResource(R.string.auto_fastest_help),
                    fontFamily = Urbanist,
                    fontSize = 13.sp,
                    color = SparkColors.textTertiary,
                    modifier = Modifier.padding(horizontal = 4.dp),
                )
                Spacer(Modifier.height(20.dp))
            }

            // Empty state
            if (loaded && servers.isEmpty()) {
                item {
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .padding(vertical = 32.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            stringResource(R.string.no_servers_available),
                            fontFamily = Urbanist,
                            fontSize = 14.sp,
                            color = SparkColors.textTertiary,
                        )
                    }
                }
            } else if (servers.isNotEmpty()) {
                // "ALL LOCATIONS" — one card holding every country group with internal dividers
                // (mirrors the Tauri page and the home StatusCard: a single surface, not per-row cards).
                item {
                    Text(
                        stringResource(R.string.all_locations),
                        fontFamily = Urbanist,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = SparkColors.textTertiary,
                        letterSpacing = 1.2.sp,
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
                    )
                    Spacer(Modifier.height(8.dp))

                    Column(
                        Modifier
                            .fillMaxWidth()
                            .shadow(
                                elevation = 16.dp,
                                shape = RoundedCornerShape(16.dp),
                                ambientColor = SparkColors.shadow,
                                spotColor = SparkColors.shadow,
                            )
                            .clip(RoundedCornerShape(16.dp))
                            .background(SparkColors.surface),
                    ) {
                        groups.forEachIndexed { gi, (country, members) ->
                            if (gi > 0) RowDivider()
                            CountryGroup(
                                country = country,
                                members = members,
                                selectedIdx = selectedIdx,
                                expanded = expandedGroups[country] ?: false,
                                onToggle = { expandedGroups[country] = !(expandedGroups[country] ?: false) },
                                onChoose = ::choose,
                            )
                        }
                    }
                    Spacer(Modifier.height(16.dp))
                }
            }
        }
    }
}

/** One country in the All-Locations card: a single tappable row, or an expandable header + city rows. */
@Composable
private fun CountryGroup(
    country: String,
    members: List<ServerInfo>,
    selectedIdx: Int?,
    expanded: Boolean,
    onToggle: () -> Unit,
    onChoose: (Int?) -> Unit,
) {
    if (members.size == 1) {
        val s = members[0]
        ServerRow(
            flag = flagEmoji(s.countryCode),
            title = serverLabel(s),
            protocol = protocolLabel(s.protocol),
            latencyMs = s.latencyMs,
            selected = selectedIdx == s.index,
            onClick = { onChoose(s.index) },
        )
        return
    }

    // Multi-member: expandable header + indented city rows.
    val bestLatency = members.mapNotNull { it.latencyMs }.minOrNull()
    val expandRotation by animateFloatAsState(
        targetValue = if (expanded) 90f else 0f,
        animationSpec = tween(200),
        label = "expand-$country",
    )
    Row(
        Modifier
            .fillMaxWidth()
            .clickable { onToggle() }
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(flagEmoji(members.firstOrNull()?.countryCode), fontSize = 21.sp)
        Text(
            country,
            fontFamily = Urbanist,
            fontSize = 15.sp,
            fontWeight = FontWeight.SemiBold,
            color = SparkColors.textPrimary,
            modifier = Modifier.weight(1f),
        )
        bestLatency?.let { LatencyPill(it) }
        Icon(
            ChevronRightIcon,
            contentDescription = stringResource(if (expanded) R.string.collapse else R.string.expand),
            tint = SparkColors.textTertiary,
            modifier = Modifier
                .size(20.dp)
                .rotate(expandRotation),
        )
    }
    if (expanded) {
        members.forEach { s ->
            RowDivider()
            ServerRow(
                flag = null,
                title = s.city?.takeIf { it.isNotBlank() } ?: serverLabel(s),
                protocol = protocolLabel(s.protocol),
                latencyMs = s.latencyMs,
                selected = selectedIdx == s.index,
                onClick = { onChoose(s.index) },
                indented = true,
            )
        }
    }
}

/** A selectable pool row: flag (or indent) + label + protocol subtitle + latency pill + ✓ when picked. */
@Composable
private fun ServerRow(
    flag: String?,
    title: String,
    protocol: String,
    latencyMs: Long?,
    selected: Boolean,
    onClick: () -> Unit,
    indented: Boolean = false,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(if (selected) SparkColors.brand.copy(alpha = 0.08f) else Color.Transparent)
            .clickable { onClick() }
            .padding(start = if (indented) 52.dp else 16.dp, end = 16.dp, top = 11.dp, bottom = 11.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (flag != null) Text(flag, fontSize = 21.sp)
        Column(Modifier.weight(1f)) {
            Text(
                title,
                fontFamily = Urbanist,
                fontSize = if (indented) 14.sp else 15.sp,
                fontWeight = if (indented) FontWeight.Medium else FontWeight.SemiBold,
                color = SparkColors.textPrimary,
            )
            if (protocol.isNotEmpty()) {
                Text(
                    protocol,
                    fontFamily = Urbanist,
                    fontSize = 12.sp,
                    color = SparkColors.textTertiary,
                )
            }
        }
        latencyMs?.let { LatencyPill(it) }
        if (selected) Text("✓", fontSize = 18.sp, color = SparkColors.brand)
    }
}

@Composable
private fun RowDivider() {
    Box(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .height(1.dp)
            .background(SparkColors.border),
    )
}

// --- Inline vector icons ---

// autoMirror flips direction-sensitive icons (chevrons) in RTL locales (fa); custom ImageVectors
// are NOT auto-mirrored by Compose otherwise.
private fun strokeVector(name: String, autoMirror: Boolean = false, build: ImageVector.Builder.() -> Unit): ImageVector =
    ImageVector.Builder(
        name = name,
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
        autoMirror = autoMirror,
    ).apply(build).build()

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

private val BackChevronIcon: ImageVector = strokeVector("BackChevron", autoMirror = true) {
    stroke(2f) { moveTo(15f, 18f); lineTo(9f, 12f); lineTo(15f, 6f) }
}

private val ChevronRightIcon: ImageVector = strokeVector("ChevronRight", autoMirror = true) {
    stroke(2f) { moveTo(9f, 18f); lineTo(15f, 12f); lineTo(9f, 6f) }
}
