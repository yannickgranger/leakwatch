package io.github.yannickgranger.leakwatch.entry

import android.content.Context
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import io.github.yannickgranger.leakwatch.adapter.FileArchiveStore
import io.github.yannickgranger.leakwatch.adapter.FileDomainRuleStore
import io.github.yannickgranger.leakwatch.adapter.PrefsBlockStore
import io.github.yannickgranger.leakwatch.adapter.UsageAccess
import io.github.yannickgranger.leakwatch.adapter.WallClock
import io.github.yannickgranger.leakwatch.domain.AppStats
import io.github.yannickgranger.leakwatch.domain.AppSummary
import io.github.yannickgranger.leakwatch.domain.ArchiveWriter
import io.github.yannickgranger.leakwatch.domain.BlockPolicy
import io.github.yannickgranger.leakwatch.domain.DomainPolicy
import io.github.yannickgranger.leakwatch.domain.DomainRule
import io.github.yannickgranger.leakwatch.domain.DomainRules
import io.github.yannickgranger.leakwatch.domain.RuleAction
import io.github.yannickgranger.leakwatch.domain.OffenderRow
import io.github.yannickgranger.leakwatch.domain.OffendersReport

object Capture {
    private val runningState = MutableStateFlow(false)
    private val appsState = MutableStateFlow<List<AppSummary>>(emptyList())
    private val stoppedOnce = MutableStateFlow(false)
    private val usageAccessState = MutableStateFlow(true)
    private val offendersState = MutableStateFlow<List<OffenderRow>>(emptyList())
    val offenders: StateFlow<List<OffenderRow>> = offendersState

    val running: StateFlow<Boolean> = runningState
    val apps: StateFlow<List<AppSummary>> = appsState
    val stoppedAfterRun: StateFlow<Boolean> = stoppedOnce
    val usageAccess: StateFlow<Boolean> = usageAccessState

    fun checkUsageAccess(context: Context) {
        usageAccessState.value = UsageAccess.granted(context)
    }

    @Volatile
    private var policy: BlockPolicy? = null

    @Volatile
    var stopAction: (() -> Unit)? = null

    fun blocks(context: Context): BlockPolicy = policy ?: synchronized(this) {
        policy ?: BlockPolicy(PrefsBlockStore(context.applicationContext)).also { policy = it }
    }

    @Volatile
    private var domainPolicy: DomainPolicy? = null

    fun domains(context: Context): DomainPolicy = domainPolicy ?: synchronized(this) {
        domainPolicy ?: run {
            val app = context.applicationContext
            val defaults = runCatching { app.assets.open(DEFAULTS).bufferedReader().use { it.readText() } }.getOrDefault("")
            DomainPolicy(FileDomainRuleStore(File(app.filesDir, RULES)), DomainRules.defaults(defaults))
        }.also { domainPolicy = it }
    }

    private val rulesState = MutableStateFlow<List<DomainRule>>(emptyList())
    val rules: StateFlow<List<DomainRule>> = rulesState

    fun loadRules(context: Context) {
        rulesState.value = domains(context).rules()
    }

    fun putRule(context: Context, pattern: String, packageName: String?, action: RuleAction) {
        val p = domains(context)
        p.put(DomainRule(packageName ?: DomainRule.ALL, pattern, action))
        rulesState.value = p.rules()
    }

    fun removeRule(context: Context, pattern: String, packageName: String?) {
        val p = domains(context)
        p.remove(packageName ?: DomainRule.ALL, pattern)
        rulesState.value = p.rules()
    }

    fun restoreDefaults(context: Context) {
        val p = domains(context)
        p.restoreDefaults()
        rulesState.value = p.rules()
    }

    fun archiveRoot(context: Context): File = File(context.getExternalFilesDir(null) ?: context.filesDir, "archive")

    fun setRunning(value: Boolean) {
        if (!value && runningState.value) stoppedOnce.value = true
        runningState.value = value
    }

    private fun prefs(context: Context) = context.applicationContext.getSharedPreferences("capture", Context.MODE_PRIVATE)

    fun wanted(context: Context): Boolean = prefs(context).getBoolean(KEY_WANTED, false)

    fun setWanted(context: Context, value: Boolean) {
        prefs(context).edit().putBoolean(KEY_WANTED, value).apply()
    }

    fun offerSeen(context: Context): Boolean = prefs(context).getBoolean(KEY_OFFER, false)

    fun setOfferSeen(context: Context) {
        prefs(context).edit().putBoolean(KEY_OFFER, true).apply()
    }

    fun report(context: Context): OffendersReport = OffendersReport(FileArchiveStore(archiveRoot(context)))

    fun publishOffenders(rows: List<OffenderRow>) {
        offendersState.value = rows
    }

    fun loadOffenders(context: Context) {
        val r = report(context)
        val rows = r.read()
        offendersState.value = if (rows.isEmpty() && !runningState.value) r.write(blocks(context).blocked()) else rows
    }

    private const val KEY_WANTED = "wanted"
    private const val DEFAULTS = "blocklist-default.txt"
    private const val RULES = "domain-rules.tsv"
    private const val KEY_OFFER = "offer_seen"

    fun publish(apps: List<AppSummary>) {
        appsState.value = apps
    }

    fun loadToday(context: Context) {
        if (runningState.value) return
        val writer = ArchiveWriter(FileArchiveStore(archiveRoot(context)), WallClock)
        writer.loadToday()
        appsState.value = AppStats.summarize(writer.today(), writer.blockedDnsToday())
    }
}
