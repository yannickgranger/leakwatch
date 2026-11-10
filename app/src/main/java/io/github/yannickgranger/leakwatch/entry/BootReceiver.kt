package io.github.yannickgranger.leakwatch.entry

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!Capture.wanted(context)) return
        val ready = runCatching { VpnService.prepare(context) == null }.getOrDefault(false)
        if (!ready) return
        runCatching {
            ContextCompat.startForegroundService(context, Intent(context, LeakWatchVpnService::class.java).setAction(LeakWatchVpnService.ACTION_START))
        }
    }
}
