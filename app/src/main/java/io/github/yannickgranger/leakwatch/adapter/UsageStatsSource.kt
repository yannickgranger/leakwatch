package io.github.yannickgranger.leakwatch.adapter

import android.Manifest
import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Process
import io.github.yannickgranger.leakwatch.port.UsageEvent
import io.github.yannickgranger.leakwatch.port.UsageEventKind
import io.github.yannickgranger.leakwatch.port.UsageSource

class UsageStatsSource(context: Context) : UsageSource {
    private val app = context.applicationContext
    private val usm = app.getSystemService(UsageStatsManager::class.java)

    override fun hasAccess(): Boolean = UsageAccess.granted(app)

    override fun events(fromMs: Long, toMs: Long): List<UsageEvent> {
        val out = ArrayList<UsageEvent>()
        val q = usm?.queryEvents(fromMs, toMs) ?: return out
        val e = UsageEvents.Event()
        while (q.hasNextEvent()) {
            q.getNextEvent(e)
            val kind = when (e.eventType) {
                UsageEvents.Event.ACTIVITY_RESUMED -> UsageEventKind.RESUMED
                UsageEvents.Event.ACTIVITY_PAUSED -> UsageEventKind.PAUSED
                UsageEvents.Event.SCREEN_INTERACTIVE -> UsageEventKind.SCREEN_ON
                UsageEvents.Event.SCREEN_NON_INTERACTIVE -> UsageEventKind.SCREEN_OFF
                else -> null
            } ?: continue
            out += UsageEvent(e.timeStamp, e.packageName, kind)
        }
        return out
    }
}

object UsageAccess {
    fun granted(context: Context): Boolean {
        val ops = context.getSystemService(AppOpsManager::class.java) ?: return false
        val mode = runCatching { ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), context.packageName) }
            .getOrDefault(AppOpsManager.MODE_ERRORED)
        return if (mode == AppOpsManager.MODE_DEFAULT) {
            context.checkSelfPermission(Manifest.permission.PACKAGE_USAGE_STATS) == PackageManager.PERMISSION_GRANTED
        } else {
            mode == AppOpsManager.MODE_ALLOWED
        }
    }
}
