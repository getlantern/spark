package org.getlantern.spark.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue

@Composable
fun SparkApp() {
    var onServers by remember { mutableStateOf(false) }
    SparkTheme {
        if (onServers) ServersScreen(onBack = { onServers = false })
        else HomeScreen(onOpenServers = { onServers = true })
    }
}
