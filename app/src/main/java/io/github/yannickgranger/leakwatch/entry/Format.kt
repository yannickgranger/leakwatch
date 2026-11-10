package io.github.yannickgranger.leakwatch.entry

import java.util.Locale

object Format {
    fun reasons(list: List<String>): String = list.joinToString(", ") { reason(it) }

    fun reason(r: String): String = when (r) {
        "tracker" -> "tracker"
        "telemetry_name" -> "telemetry"
        "screen_off" -> "screen off"
        "background" -> "in background"
        "not_used_today" -> "not opened today"
        "cleartext_data" -> "data in clear"
        "bulk_upload" -> "big upload"
        else -> r.replace('_', ' ')
    }

    fun age(ms: Long): String {
        val s = maxOf(0L, ms / 1000)
        return when {
            s < 60 -> "$s s"
            s < 3600 -> "${s / 60} min"
            else -> "${s / 3600} h"
        }
    }

    fun bytes(n: Long): String = when {
        n < 1024 -> "$n B"
        n < 1024 * 1024 -> String.format(Locale.US, "%.1f KB", n / 1024.0)
        n < 1024L * 1024 * 1024 -> String.format(Locale.US, "%.1f MB", n / (1024.0 * 1024))
        else -> String.format(Locale.US, "%.2f GB", n / (1024.0 * 1024 * 1024))
    }
}
