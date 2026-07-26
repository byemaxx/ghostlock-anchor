package com.anchor.bootstrap

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.anchor.bootstrap.ui.theme.AnchorTheme
import kotlinx.coroutines.delay

class MainActivity : ComponentActivity() {
    private lateinit var controller: BootstrapController
    private var snapshot by mutableStateOf(BootstrapSnapshot.empty())
    private var basicInfo by mutableStateOf(BootstrapBasicInfo.loading())
    private var hasRunInCurrentSession = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        controller = BootstrapController(applicationContext)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        refreshUi()
        enableEdgeToEdge()
        setContent {
            AnchorTheme {
                BootstrapScreen(
                    snapshot = snapshot,
                    basicInfo = basicInfo,
                    onRefresh = ::refreshUi,
                    onRun = ::startBootstrap,
                    onStop = ::stopBootstrap,
                    onClearLog = ::clearLog,
                    onShowDetailedDiagnostics = controller::detailedDiagnostics,
                    onToggleAutoDisableUsbDebugging = ::setAutoDisableUsbDebugging,
                    onShowBasicInfo = ::loadBasicInfo,
                    onImport = ::importKey
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (::controller.isInitialized) refreshUi()
    }

    private fun refreshUi() {
        snapshot = controller.snapshot(hasRunInCurrentSession)
    }

    private fun startBootstrap() {
        if (!controller.isUsbDebuggingEnabled()) {
            controller.appendDiagnostic("[!] USB debugging is disabled; opening Developer options.")
            startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
            refreshUi()
            return
        }
        hasRunInCurrentSession = true
        val intent = Intent(this, BootstrapService::class.java).setAction(BootstrapService.ACTION_RUN)
        startForegroundService(intent)
        refreshUi()
    }

    private fun importKey(part: AdbKeyPart, uri: Uri) {
        controller.importKey(part, uri)
        refreshUi()
    }

    private fun stopBootstrap() {
        BootstrapService.requestStop()
        refreshUi()
    }

    private fun clearLog() {
        controller.clearLog()
        refreshUi()
    }

    private fun setAutoDisableUsbDebugging(enabled: Boolean) {
        controller.setAutoDisableUsbDebugging(enabled)
        refreshUi()
    }

    private fun loadBasicInfo() {
        basicInfo = BootstrapBasicInfo.loading()
        Thread {
            val info = controller.basicInfo()
            runOnUiThread { basicInfo = info }
        }.start()
    }
}

@Composable
private fun BootstrapScreen(
    snapshot: BootstrapSnapshot,
    basicInfo: BootstrapBasicInfo,
    onRefresh: () -> Unit,
    onRun: () -> Unit,
    onStop: () -> Unit,
    onClearLog: () -> Unit,
    onShowDetailedDiagnostics: () -> String,
    onToggleAutoDisableUsbDebugging: (Boolean) -> Unit,
    onShowBasicInfo: () -> Unit,
    onImport: (AdbKeyPart, Uri) -> Unit,
) {
    var importPart by remember { mutableStateOf<AdbKeyPart?>(null) }
    var menuOpen by remember { mutableStateOf(false) }
    var showBasicInfo by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }
    var showDetailedDiagnostics by remember { mutableStateOf(false) }
    var detailedDiagnostics by remember { mutableStateOf("") }
    val uriHandler = LocalUriHandler.current
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val part = importPart
        if (uri != null && part != null) onImport(part, uri)
        importPart = null
    }

    LaunchedEffect(Unit) {
        while (true) {
            onRefresh()
            delay(250)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Row(modifier = Modifier.fillMaxWidth()) {
            Text("Anchor", style = MaterialTheme.typography.headlineMedium)
            Spacer(Modifier.weight(1f))
            Box {
                TextButton(onClick = { menuOpen = true }) { Text("Menu") }
                DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                    DropdownMenuItem(
                        text = { Text("About") },
                        onClick = {
                            menuOpen = false
                            showAbout = true
                        }
                    )
                    DropdownMenuItem(
                        text = { Text("Status") },
                        onClick = {
                            menuOpen = false
                            showBasicInfo = true
                            onShowBasicInfo()
                        }
                    )
                    DropdownMenuItem(
                        text = { Text("Import adbkey") },
                        onClick = {
                            menuOpen = false
                            importPart = AdbKeyPart.PRIVATE
                            picker.launch(arrayOf("application/x-pem-file", "text/plain", "application/octet-stream"))
                        }
                    )
                    DropdownMenuItem(
                        text = { Text("Import adbkey.pub") },
                        onClick = {
                            menuOpen = false
                            importPart = AdbKeyPart.PUBLIC
                            picker.launch(arrayOf("text/plain", "application/octet-stream"))
                        }
                    )
                    DropdownMenuItem(
                        text = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(
                                    checked = snapshot.autoDisableUsbDebugging,
                                    onCheckedChange = null
                                )
                                Text("Disable USB debugging after completion")
                            }
                        },
                        onClick = {
                            onToggleAutoDisableUsbDebugging(!snapshot.autoDisableUsbDebugging)
                        }
                    )
                    DropdownMenuItem(
                        text = { Text("View logs") },
                        onClick = {
                            menuOpen = false
                            detailedDiagnostics = onShowDetailedDiagnostics()
                            showDetailedDiagnostics = true
                        }
                    )
                    DropdownMenuItem(
                        text = { Text("Clear logs") },
                        enabled = !snapshot.running,
                        onClick = {
                            menuOpen = false
                            onClearLog()
                        }
                    )
                }
            }
        }

        Row(modifier = Modifier.fillMaxWidth()) {
            Button(
                onClick = onRun,
                enabled = snapshot.keyStatus.ready && !snapshot.running,
                modifier = Modifier.weight(1f)
            ) { Text(if (snapshot.stopping) "Stopping…" else if (snapshot.running) "Bootstrap running…" else "Start Bootstrap") }
            Spacer(Modifier.width(8.dp))
            TextButton(
                onClick = onStop,
                enabled = snapshot.running && !snapshot.stopping,
                modifier = Modifier.width(72.dp)
            ) { Text("Stop") }
        }

        LogPanel(snapshot.log, Modifier.weight(1f))
    }

    if (showBasicInfo) {
        AlertDialog(
            onDismissRequest = { showBasicInfo = false },
            title = { Text("Status") },
            text = { Text(basicInfo.displayText()) },
            confirmButton = {
                TextButton(onClick = { showBasicInfo = false }) { Text("Close") }
            }
        )
    }

    if (showAbout) {
        AlertDialog(
            onDismissRequest = { showAbout = false },
            title = { Text("About Anchor") },
            text = {
                Text(
                    "Anchor is an Android application implementation for the" +
                        "GhostLock OnePlus project.\n\nMaintained by byemaxx."
                )
            },
            confirmButton = {
                TextButton(onClick = { uriHandler.openUri("https://github.com/byemaxx/ghostlock-anchor/") }) {
                    Text("Project page")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAbout = false }) { Text("Close") }
            }
        )
    }

    if (showDetailedDiagnostics) {
        AlertDialog(
            onDismissRequest = { showDetailedDiagnostics = false },
            title = { Text("Logs") },
            text = {
                SelectionContainer {
                    Text(
                        detailedDiagnostics.ifBlank { "No log entries yet." },
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        modifier = Modifier.heightIn(max = 480.dp).verticalScroll(rememberScrollState())
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showDetailedDiagnostics = false }) { Text("Close") }
            }
        )
    }
}

@Composable
private fun LogPanel(log: String, modifier: Modifier = Modifier) {
    val scroll = rememberScrollState()
    LaunchedEffect(log) { scroll.scrollTo(scroll.maxValue) }
    Card(modifier = modifier.fillMaxWidth()) {
        Box(modifier = Modifier.fillMaxSize()) {
            SelectionContainer {
                Text(
                    text = log.ifBlank { "No bootstrap result yet." },
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(scroll)
                        .padding(14.dp)
                )
            }
        }
    }
}
