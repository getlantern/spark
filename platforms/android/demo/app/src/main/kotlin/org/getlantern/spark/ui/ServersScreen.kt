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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.getlantern.spark.Selection
import org.getlantern.spark.ServerInfo
import org.getlantern.spark.SparkBridge
import org.getlantern.spark.parseServers
import androidx.compose.runtime.rememberCoroutineScope

@Composable
fun ServersScreen(onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    val selectedIdx by Selection.index.collectAsStateWithLifecycle()

    var servers by remember { mutableStateOf<List<ServerInfo>>(emptyList()) }
    var loaded by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        while (true) {
            servers = parseServers(SparkBridge.nativeServers())
            loaded = true
            delay(3000)
        }
    }

    val current = servers.firstOrNull { it.isCurrent }

    // Track expanded state for multi-member country groups
    val expandedGroups = remember { mutableStateMapOf<String, Boolean>() }

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
                    contentDescription = "Back",
                    tint = SparkColors.textPrimary,
                    modifier = Modifier.size(22.dp),
                )
            }
            Text(
                "Server selection",
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
                val isAuto = selectedIdx == null
                Box(
                    Modifier
                        .fillMaxWidth()
                        .shadow(
                            elevation = 8.dp,
                            shape = RoundedCornerShape(16.dp),
                            ambientColor = SparkColors.shadow,
                            spotColor = SparkColors.shadow,
                        )
                        .clip(RoundedCornerShape(16.dp))
                        .background(
                            if (isAuto) SparkColors.brand.copy(alpha = 0.08f) else SparkColors.surface,
                        )
                        .clickable {
                            Selection.index.value = null
                            scope.launch(Dispatchers.IO) {
                                SparkBridge.nativeSelectServer(-1)
                            }
                            onBack()
                        }
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        if (current != null) {
                            Text(flagEmoji(current.countryCode), fontSize = 21.sp)
                        } else {
                            Text("🌐", fontSize = 21.sp)
                        }
                        Column(Modifier.weight(1f)) {
                            Text(
                                if (current != null) serverLabel(current) else "Fastest server",
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
                }
                Spacer(Modifier.height(8.dp))
                Text(
                    "Automatically chooses the fastest location.",
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
                            "No servers available. Connect first to choose a location.",
                            fontFamily = Urbanist,
                            fontSize = 14.sp,
                            color = SparkColors.textTertiary,
                        )
                    }
                }
            } else if (servers.isNotEmpty()) {
                // "ALL LOCATIONS" header
                item {
                    Text(
                        "ALL LOCATIONS",
                        fontFamily = Urbanist,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = SparkColors.textTertiary,
                        letterSpacing = 1.2.sp,
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 4.dp),
                    )
                    Spacer(Modifier.height(8.dp))
                }

                // Group servers by country (or name or "—")
                val groups = servers
                    .groupBy { it.country?.takeIf { c -> c.isNotBlank() } ?: (it.name?.takeIf { n -> n.isNotBlank() } ?: "—") }
                    .entries
                    .sortedBy { it.key }

                items(groups, key = { it.key }) { (country, members) ->
                    val isSingle = members.size == 1
                    val isExpanded = expandedGroups[country] ?: false

                    Box(
                        Modifier
                            .fillMaxWidth()
                            .shadow(
                                elevation = 4.dp,
                                shape = RoundedCornerShape(12.dp),
                                ambientColor = SparkColors.shadow,
                                spotColor = SparkColors.shadow,
                            )
                            .clip(RoundedCornerShape(12.dp))
                            .background(SparkColors.surface),
                    ) {
                        Column {
                            if (isSingle) {
                                val s = members[0]
                                val isSelected = selectedIdx == s.index
                                Row(
                                    Modifier
                                        .fillMaxWidth()
                                        .background(
                                            if (isSelected) SparkColors.brand.copy(alpha = 0.08f)
                                            else Color.Transparent,
                                        )
                                        .clickable {
                                            Selection.index.value = s.index
                                            scope.launch(Dispatchers.IO) {
                                                SparkBridge.nativeSelectServer(s.index)
                                            }
                                            onBack()
                                        }
                                        .padding(horizontal = 16.dp, vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Text(flagEmoji(s.countryCode), fontSize = 21.sp)
                                    Column(Modifier.weight(1f)) {
                                        Text(
                                            serverLabel(s),
                                            fontFamily = Urbanist,
                                            fontSize = 15.sp,
                                            fontWeight = FontWeight.SemiBold,
                                            color = SparkColors.textPrimary,
                                        )
                                        val proto = protocolLabel(s.protocol)
                                        if (proto.isNotEmpty()) {
                                            Text(
                                                proto,
                                                fontFamily = Urbanist,
                                                fontSize = 12.sp,
                                                color = SparkColors.textTertiary,
                                            )
                                        }
                                    }
                                    s.latencyMs?.let { LatencyPill(it) }
                                    if (isSelected) {
                                        Text("✓", fontSize = 18.sp, color = SparkColors.brand)
                                    }
                                }
                            } else {
                                // Multi-member: expandable group header
                                val bestLatency = members.mapNotNull { it.latencyMs }.minOrNull()
                                val expandRotation by animateFloatAsState(
                                    targetValue = if (isExpanded) 90f else 0f,
                                    animationSpec = tween(200),
                                    label = "expand-$country",
                                )
                                // Use the countryCode of the first member for the flag
                                val groupFlag = members.firstOrNull()?.countryCode

                                Row(
                                    Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            expandedGroups[country] = !isExpanded
                                        }
                                        .padding(horizontal = 16.dp, vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Text(flagEmoji(groupFlag), fontSize = 21.sp)
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
                                        contentDescription = if (isExpanded) "Collapse" else "Expand",
                                        tint = SparkColors.textTertiary,
                                        modifier = Modifier
                                            .size(20.dp)
                                            .rotate(expandRotation),
                                    )
                                }

                                // City rows when expanded
                                if (isExpanded) {
                                    RowDivider()
                                    members.forEachIndexed { idx, s ->
                                        val isSelected = selectedIdx == s.index
                                        Row(
                                            Modifier
                                                .fillMaxWidth()
                                                .background(
                                                    if (isSelected) SparkColors.brand.copy(alpha = 0.08f)
                                                    else Color.Transparent,
                                                )
                                                .clickable {
                                                    Selection.index.value = s.index
                                                    scope.launch(Dispatchers.IO) {
                                                        SparkBridge.nativeSelectServer(s.index)
                                                    }
                                                    onBack()
                                                }
                                                .padding(start = 52.dp, end = 16.dp, top = 10.dp, bottom = 10.dp),
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                                        ) {
                                            val cityName = s.city?.takeIf { it.isNotBlank() } ?: serverLabel(s)
                                            Column(Modifier.weight(1f)) {
                                                Text(
                                                    cityName,
                                                    fontFamily = Urbanist,
                                                    fontSize = 14.sp,
                                                    fontWeight = FontWeight.Medium,
                                                    color = SparkColors.textPrimary,
                                                )
                                                val proto = protocolLabel(s.protocol)
                                                if (proto.isNotEmpty()) {
                                                    Text(
                                                        proto,
                                                        fontFamily = Urbanist,
                                                        fontSize = 12.sp,
                                                        color = SparkColors.textTertiary,
                                                    )
                                                }
                                            }
                                            s.latencyMs?.let { LatencyPill(it) }
                                            if (isSelected) {
                                                Text("✓", fontSize = 18.sp, color = SparkColors.brand)
                                            }
                                        }
                                        if (idx < members.size - 1) RowDivider()
                                    }
                                }
                            }
                        }
                    }

                    // 1px divider between groups
                    Spacer(Modifier.height(1.dp))
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .height(1.dp)
                            .background(SparkColors.border),
                    )
                    Spacer(Modifier.height(8.dp))
                }
            }

            item { Spacer(Modifier.height(16.dp)) }
        }
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

private fun strokeVector(name: String, build: ImageVector.Builder.() -> Unit): ImageVector =
    ImageVector.Builder(
        name = name,
        defaultWidth = 24.dp,
        defaultHeight = 24.dp,
        viewportWidth = 24f,
        viewportHeight = 24f,
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

private val BackChevronIcon: ImageVector = strokeVector("BackChevron") {
    stroke(2f) { moveTo(15f, 18f); lineTo(9f, 12f); lineTo(15f, 6f) }
}

private val ChevronRightIcon: ImageVector = strokeVector("ChevronRight") {
    stroke(2f) { moveTo(9f, 18f); lineTo(15f, 12f); lineTo(9f, 6f) }
}
