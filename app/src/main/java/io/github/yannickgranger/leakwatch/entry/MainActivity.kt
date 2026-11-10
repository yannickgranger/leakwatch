package io.github.yannickgranger.leakwatch.entry

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.OpenableColumns
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import io.github.yannickgranger.leakwatch.BuildConfig
import io.github.yannickgranger.leakwatch.R
import io.github.yannickgranger.leakwatch.domain.DomainRule
import io.github.yannickgranger.leakwatch.domain.RuleAction
import io.github.yannickgranger.leakwatch.domain.WgConfigParser

class MainActivity : ComponentActivity() {
    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) launchService()
    }
    private val picker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) importFrom(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) {
            handle(intent)
            handleShared(intent)
        }
        setContent {
            LeakWatchScreen(
                actions = object : ScreenActions {
                    override fun start() {
                        askNotifications()
                        startCapture()
                    }
                    override fun stop() = stopCapture()
                    override fun export() = exportArchive()
                    override fun openWireGuard() = openWireGuardApp()
                    override fun wireGuardInstalled(): Boolean = packageManager.getLaunchIntentForPackage(WIREGUARD) != null
                    override fun isBlocked(uid: Int): Boolean = Capture.blocks(this@MainActivity).isBlocked(uid)
                    override fun setBlocked(uid: Int, blocked: Boolean) {
                        val p = Capture.blocks(this@MainActivity)
                        if (blocked) p.block(uid) else p.unblock(uid)
                    }
                    override fun appInfo(pkg: String) = openAppInfo(pkg)
                    override fun uninstall(pkg: String) = uninstallApp(pkg)
                    override fun openUsageAccess() = openUsageAccessSettings()
                    override fun importConfig() {
                        if (BuildConfig.WIREGUARD) picker.launch(arrayOf(ANY_TYPE))
                    }
                    override fun chooseTunnel(name: String, text: String) = saveTunnel(name, text)
                    override fun removeLink() = WireGuardLink.remove(applicationContext)
                    override fun showOffer(): Boolean = !Capture.offerSeen(this@MainActivity)
                    override fun dismissOffer() = Capture.setOfferSeen(this@MainActivity)
                    override fun batteryUnrestricted(): Boolean = getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName)
                    override fun openBatterySettings() = askBatteryExemption()
                    override fun blockDomain(pattern: String, pkg: String?) = Capture.putRule(applicationContext, pattern, pkg, RuleAction.BLOCK)
                    override fun allowDomain(pattern: String, pkg: String) = Capture.putRule(applicationContext, pattern, pkg, RuleAction.ALLOW)
                    override fun removeRule(scope: String, pattern: String) = Capture.removeRule(applicationContext, pattern, scope.takeIf { it != DomainRule.ALL })
                    override fun restoreDefaults() = Capture.restoreDefaults(applicationContext)
                    override fun openVpnSettings() {
                        runCatching { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
                    }
                },
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handle(intent)
        handleShared(intent)
    }

    private fun handleShared(intent: Intent?) {
        if (!BuildConfig.WIREGUARD) return
        val uri = when (intent?.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND -> if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java) else legacyStream(intent)
            else -> null
        } ?: return
        importFrom(uri)
    }

    @Suppress("DEPRECATION")
    private fun legacyStream(intent: Intent): Uri? = intent.getParcelableExtra(Intent.EXTRA_STREAM)

    private fun displayName(uri: Uri): String {
        val fromProvider = runCatching {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        }.getOrNull()
        return fromProvider ?: uri.lastPathSegment ?: "wireguard.conf"
    }

    private fun importFrom(uri: Uri) {
        if (!BuildConfig.WIREGUARD) return
        lifecycleScope.launch {
            val tunnels = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: return@runCatching null
                    if (bytes.size > MAX_IMPORT) return@runCatching null
                    WgConfigParser.tunnels(displayName(uri), bytes)
                }.getOrNull()
            }
            when {
                tunnels == null -> WireGuardLink.setMessage(getString(R.string.link_unreadable))
                tunnels.isEmpty() -> WireGuardLink.setMessage(getString(R.string.link_none_in_zip))
                tunnels.size == 1 -> saveTunnel(tunnels[0].first, tunnels[0].second)
                else -> WireGuardLink.offerChoices(tunnels)
            }
        }
    }

    private fun saveTunnel(name: String, text: String) {
        lifecycleScope.launch {
            val refused = withContext(Dispatchers.IO) { runCatching { WireGuardLink.import(applicationContext, name, text) }.getOrElse { getString(R.string.link_unreadable) } }
            WireGuardLink.offerChoices(emptyList())
            WireGuardLink.setMessage(refused ?: getString(R.string.link_saved))
        }
    }

    @Suppress("BatteryLife")
    private fun askBatteryExemption() {
        val direct = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName"))
        runCatching { startActivity(direct) }.onFailure { runCatching { startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) } }
    }

    override fun onResume() {
        super.onResume()
        Capture.checkUsageAccess(this)
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching { Capture.loadToday(applicationContext) }
            if (BuildConfig.WIREGUARD) runCatching { WireGuardLink.refresh(applicationContext) }
            runCatching { Capture.loadOffenders(applicationContext) }
            runCatching { Capture.loadRules(applicationContext) }
        }
    }

    private fun handle(intent: Intent?) {
        val pattern = intent?.getStringExtra(EXTRA_PATTERN)
        val pkg = intent?.getStringExtra(EXTRA_PACKAGE)?.takeIf { it.isNotBlank() }
        when (intent?.getStringExtra(EXTRA_CMD)) {
            "start" -> startCapture()
            "stop" -> stopCapture()
            "block_domain" -> if (!pattern.isNullOrBlank()) Capture.putRule(applicationContext, pattern, pkg, RuleAction.BLOCK)
            "remove_rule" -> if (!pattern.isNullOrBlank()) Capture.removeRule(applicationContext, pattern, pkg)
        }
    }

    private fun askNotifications() {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }

    private fun startCapture() {
        val prepare = try {
            VpnService.prepare(this)
        } catch (e: Exception) {
            null
        }
        if (prepare != null) consent.launch(prepare) else launchService()
    }

    private fun launchService() {
        ContextCompat.startForegroundService(this, Intent(this, LeakWatchVpnService::class.java).setAction(LeakWatchVpnService.ACTION_START))
    }

    private fun stopCapture() {
        Capture.setWanted(this, false)
        val stop = Capture.stopAction
        if (stop != null) {
            stop()
        } else {
            runCatching { startService(Intent(this, LeakWatchVpnService::class.java).setAction(LeakWatchVpnService.ACTION_STOP)) }
        }
    }

    private fun exportArchive() {
        lifecycleScope.launch {
            val file = withContext(Dispatchers.IO) { runCatching { Export.zip(applicationContext) }.getOrNull() }
            if (file == null) {
                Toast.makeText(this@MainActivity, R.string.export_empty, Toast.LENGTH_SHORT).show()
            } else {
                startActivity(Export.shareIntent(this@MainActivity, file, getString(R.string.export_title)))
            }
        }
    }

    private fun openWireGuardApp() {
        packageManager.getLaunchIntentForPackage(WIREGUARD)?.let { startActivity(it) }
    }

    private fun openUsageAccessSettings() {
        val direct = Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, Uri.parse("package:$packageName"))
        runCatching { startActivity(direct) }.onFailure { runCatching { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) } }
    }

    private fun openAppInfo(pkg: String) {
        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg")))
    }

    @Suppress("DEPRECATION")
    private fun uninstallApp(pkg: String) {
        startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
    }

    companion object {
        const val EXTRA_CMD = "cmd"
        const val EXTRA_PATTERN = "pattern"
        const val EXTRA_PACKAGE = "package"
        private const val MAX_IMPORT = 1024 * 1024
        private val ANY_TYPE = listOf("*", "*").joinToString("/")
        private const val WIREGUARD = "com.wireguard.android"
    }
}
