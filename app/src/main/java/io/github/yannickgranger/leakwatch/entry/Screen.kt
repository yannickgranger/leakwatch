package io.github.yannickgranger.leakwatch.entry

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.yannickgranger.leakwatch.BuildConfig
import io.github.yannickgranger.leakwatch.R
import io.github.yannickgranger.leakwatch.domain.AppSummary
import io.github.yannickgranger.leakwatch.domain.DomainRule
import io.github.yannickgranger.leakwatch.domain.RuleAction
import io.github.yannickgranger.leakwatch.domain.OffenderRow

interface ScreenActions {
    fun start()
    fun stop()
    fun export()
    fun openWireGuard()
    fun wireGuardInstalled(): Boolean
    fun isBlocked(uid: Int): Boolean
    fun setBlocked(uid: Int, blocked: Boolean)
    fun appInfo(pkg: String)
    fun uninstall(pkg: String)
    fun openUsageAccess()
    fun importConfig()
    fun chooseTunnel(name: String, text: String)
    fun removeLink()
    fun showOffer(): Boolean
    fun dismissOffer()
    fun batteryUnrestricted(): Boolean
    fun openBatterySettings()
    fun openVpnSettings()
    fun blockDomain(pattern: String, pkg: String?)
    fun allowDomain(pattern: String, pkg: String)
    fun removeRule(scope: String, pattern: String)
    fun restoreDefaults()
}

@Composable
fun LeakWatchScreen(actions: ScreenActions) {
    val running by Capture.running.collectAsStateWithLifecycle()
    val apps by Capture.apps.collectAsStateWithLifecycle()
    val stoppedAfterRun by Capture.stoppedAfterRun.collectAsStateWithLifecycle()
    val usageAccess by Capture.usageAccess.collectAsStateWithLifecycle()
    val offenders by Capture.offenders.collectAsStateWithLifecycle()
    val link by WireGuardLink.summary.collectAsStateWithLifecycle()
    val handshake by WireGuardLink.lastHandshake.collectAsStateWithLifecycle()
    val choices by WireGuardLink.choices.collectAsStateWithLifecycle()
    val message by WireGuardLink.message.collectAsStateWithLifecycle()
    var selectedUid by rememberSaveable { mutableStateOf<Int?>(null) }
    var showLink by rememberSaveable { mutableStateOf(false) }
    var showRules by rememberSaveable { mutableStateOf(false) }
    val rules by Capture.rules.collectAsStateWithLifecycle()
    var tab by rememberSaveable { mutableStateOf(0) }
    MaterialTheme {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.safeDrawingPadding().padding(16.dp)) {
                val selected = apps.firstOrNull { it.uid == selectedUid }
                when {
                    BuildConfig.WIREGUARD && (showLink || choices.isNotEmpty()) -> {
                        BackHandler { showLink = false }
                        LinkScreen(link, choices, message, actions) { showLink = false }
                    }
                    showRules -> {
                        BackHandler { showRules = false }
                        RulesScreen(rules, actions) { showRules = false }
                    }
                    selectedUid != null && selected != null -> {
                        BackHandler { selectedUid = null }
                        AppDetail(selected, actions) { selectedUid = null }
                    }
                    else -> {
                        Home(running, stoppedAfterRun, usageAccess, BuildConfig.WIREGUARD, link != null, handshake, actions, { showRules = true }) { showLink = true }
                        PrimaryTabRow(selectedTabIndex = tab) {
                            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text(stringResource(R.string.tab_offenders)) })
                            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text(stringResource(R.string.tab_today)) })
                        }
                        if (tab == 0) Offenders(offenders, actions) else Today(apps) { selectedUid = it }
                    }
                }
            }
        }
    }
}

@Composable
private fun Offenders(rows: List<OffenderRow>, actions: ScreenActions) {
    if (rows.isEmpty()) {
        Text(stringResource(R.string.no_offenders), Modifier.padding(vertical = 8.dp))
        return
    }
    LazyColumn(Modifier.fillMaxWidth()) {
        items(rows, key = { it.uid }) { row ->
            var blocked by remember(row.uid) { mutableStateOf(actions.isBlocked(row.uid)) }
            val pkg = row.packages.firstOrNull()
            Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                Text(row.label, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.offender_row, row.daysSuspicious, Format.bytes(row.screenOffBytesOut7d)), style = MaterialTheme.typography.bodySmall)
                if (row.reasons.isNotEmpty()) {
                    Text(Format.reasons(row.reasons), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        actions.setBlocked(row.uid, !blocked)
                        blocked = !blocked
                    }) { Text(stringResource(if (blocked) R.string.unblock else R.string.block)) }
                    OutlinedButton(enabled = pkg != null, onClick = { pkg?.let(actions::appInfo) }) { Text(stringResource(R.string.app_info)) }
                    OutlinedButton(enabled = pkg != null, onClick = { pkg?.let(actions::uninstall) }) { Text(stringResource(R.string.uninstall)) }
                }
            }
            HorizontalDivider()
        }
    }
}

@Composable
private fun LinkScreen(link: LinkSummary?, choices: List<Pair<String, String>>, message: String?, actions: ScreenActions, onBack: () -> Unit) {
    TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
    Text(stringResource(R.string.tab_link), style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(8.dp))
    if (link == null) {
        Text(stringResource(R.string.link_off))
    } else {
        Text(stringResource(R.string.link_on, link.name))
        Text(stringResource(R.string.link_details, link.addresses, link.endpoint, link.allowedIps), style = MaterialTheme.typography.bodySmall)
    }
    if (message != null) {
        Spacer(Modifier.height(8.dp))
        Text(message, color = MaterialTheme.colorScheme.primary)
    }
    Spacer(Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = actions::importConfig) { Text(stringResource(R.string.link_import)) }
        if (link != null) OutlinedButton(onClick = actions::removeLink) { Text(stringResource(R.string.link_remove)) }
    }
    if (choices.isNotEmpty()) {
        Spacer(Modifier.height(16.dp))
        Text(stringResource(R.string.link_pick), style = MaterialTheme.typography.titleMedium)
        LazyColumn(Modifier.fillMaxWidth()) {
            items(choices, key = { it.first }) { (name, text) ->
                Text(name, Modifier.fillMaxWidth().clickable { actions.chooseTunnel(name, text) }.padding(vertical = 12.dp), fontWeight = FontWeight.Bold)
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun Home(running: Boolean, stoppedAfterRun: Boolean, usageAccess: Boolean, tunnelBuilt: Boolean, linked: Boolean, handshake: Long?, actions: ScreenActions, onRules: () -> Unit, onLink: () -> Unit) {
    Text(stringResource(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
    Text(stringResource(if (running) R.string.status_on else R.string.status_off))
    Spacer(Modifier.height(8.dp))
    if (!running) Text(stringResource(R.string.wireguard_note), style = MaterialTheme.typography.bodySmall)
    if (tunnelBuilt && !linked) {
        Text(stringResource(R.string.link_off), style = MaterialTheme.typography.bodySmall)
    } else if (tunnelBuilt && running) {
        val text = if (handshake != null) {
            stringResource(R.string.link_handshake, Format.age(System.currentTimeMillis() - handshake))
        } else {
            stringResource(R.string.link_waiting)
        }
        Text(text, style = MaterialTheme.typography.bodySmall)
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        if (tunnelBuilt) TextButton(onClick = onLink) { Text(stringResource(R.string.tab_link)) }
        TextButton(onClick = onRules) { Text(stringResource(R.string.rules_title)) }
    }
    var offer by remember { mutableStateOf(actions.showOffer()) }
    if (offer) {
        Text(stringResource(R.string.offer_note), style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!actions.batteryUnrestricted()) {
                TextButton(onClick = {
                    actions.dismissOffer()
                    actions.openBatterySettings()
                }) { Text(stringResource(R.string.offer_battery)) }
            }
            TextButton(onClick = {
                actions.dismissOffer()
                actions.openVpnSettings()
            }) { Text(stringResource(R.string.offer_vpn)) }
            TextButton(onClick = {
                actions.dismissOffer()
                offer = false
            }) { Text(stringResource(R.string.offer_dismiss)) }
        }
    }
    if (!usageAccess) {
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.usage_note), style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = actions::openUsageAccess) { Text(stringResource(R.string.usage_button)) }
    }
    Spacer(Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        if (running) {
            Button(onClick = actions::stop) { Text(stringResource(R.string.stop)) }
        } else {
            Button(onClick = actions::start) { Text(stringResource(R.string.start)) }
        }
        OutlinedButton(onClick = actions::export) { Text(stringResource(R.string.export)) }
    }
    val wireGuard = remember(running) { actions.wireGuardInstalled() }
    if (!running && stoppedAfterRun && wireGuard) {
        TextButton(onClick = actions::openWireGuard) { Text(stringResource(R.string.open_wireguard)) }
    }
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun Today(apps: List<AppSummary>, onSelect: (Int) -> Unit) {
    if (apps.isEmpty()) {
        Text(stringResource(R.string.no_apps))
    }
    LazyColumn(Modifier.fillMaxWidth()) {
        items(apps, key = { it.uid }) { app ->
            Column(
                Modifier.fillMaxWidth().clickable { onSelect(app.uid) }.padding(vertical = 8.dp),
            ) {
                Text(app.label, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.app_row, Format.bytes(app.bytesOut), app.trackerFlows), style = MaterialTheme.typography.bodySmall)
                if (app.reasons.isNotEmpty()) {
                    Text(
                        stringResource(R.string.app_suspicious, Format.bytes(app.suspiciousBytesOut), Format.reasons(app.reasons)),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            HorizontalDivider()
        }
    }
}

@Composable
private fun AppDetail(app: AppSummary, actions: ScreenActions, onBack: () -> Unit) {
    var blocked by remember(app.uid) { mutableStateOf(actions.isBlocked(app.uid)) }
    val pkg = app.packages.firstOrNull()
    TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
    Text(app.label, style = MaterialTheme.typography.headlineSmall)
    if (pkg != null) Text(pkg, style = MaterialTheme.typography.bodySmall)
    if (blocked) Text(stringResource(R.string.blocked_note))
    if (app.blockedAttempts > 0) Text(stringResource(R.string.blocked_attempts, app.blockedAttempts), style = MaterialTheme.typography.bodySmall)
    Spacer(Modifier.height(8.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = {
            actions.setBlocked(app.uid, !blocked)
            blocked = !blocked
        }) { Text(stringResource(if (blocked) R.string.unblock else R.string.block)) }
        OutlinedButton(enabled = pkg != null, onClick = { pkg?.let(actions::appInfo) }) { Text(stringResource(R.string.app_info)) }
        OutlinedButton(enabled = pkg != null, onClick = { pkg?.let(actions::uninstall) }) { Text(stringResource(R.string.uninstall)) }
    }
    Spacer(Modifier.height(16.dp))
    Text(stringResource(R.string.destinations), style = MaterialTheme.typography.titleMedium)
    LazyColumn(Modifier.fillMaxWidth()) {
        items(app.destinations, key = { it.name }) { d ->
            Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(d.name, fontWeight = FontWeight.Bold)
                    if (d.tracker) Text(stringResource(R.string.tracker), color = MaterialTheme.colorScheme.error)
                }
                Text(stringResource(R.string.dest_row, Format.bytes(d.bytesOut), Format.bytes(d.bytesIn), d.flows), style = MaterialTheme.typography.bodySmall)
                if (d.reasons.isNotEmpty()) {
                    Text(Format.reasons(d.reasons), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (pkg != null) TextButton(onClick = { actions.blockDomain(d.name, pkg) }) { Text(stringResource(R.string.block_here)) }
                    TextButton(onClick = { actions.blockDomain(d.name, null) }) { Text(stringResource(R.string.block_all)) }
                    if (pkg != null) TextButton(onClick = { actions.allowDomain(d.name, pkg) }) { Text(stringResource(R.string.allow)) }
                }
            }
            HorizontalDivider()
        }
    }
}

@Composable
private fun RulesScreen(rules: List<DomainRule>, actions: ScreenActions, onBack: () -> Unit) {
    TextButton(onClick = onBack) { Text(stringResource(R.string.back)) }
    Text(stringResource(R.string.rules_title), style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(8.dp))
    OutlinedButton(onClick = actions::restoreDefaults) { Text(stringResource(R.string.restore_defaults)) }
    Spacer(Modifier.height(8.dp))
    if (rules.isEmpty()) Text(stringResource(R.string.rules_empty))
    LazyColumn(Modifier.fillMaxWidth()) {
        items(rules, key = { it.scope + " " + it.pattern }) { r ->
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.SpaceBetween) {
                Column(Modifier.weight(1f)) {
                    Text(r.pattern, fontWeight = FontWeight.Bold)
                    Text(
                        stringResource(
                            R.string.rule_row,
                            stringResource(if (r.action == RuleAction.BLOCK) R.string.rule_block else R.string.rule_allow),
                            if (r.global) stringResource(R.string.rule_all_apps) else r.scope,
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                TextButton(onClick = { actions.removeRule(r.scope, r.pattern) }) { Text(stringResource(R.string.remove)) }
            }
            HorizontalDivider()
        }
    }
}
