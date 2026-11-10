package io.github.yannickgranger.leakwatch.entry

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import io.github.yannickgranger.leakwatch.BuildConfig
import io.github.yannickgranger.leakwatch.R
import io.github.yannickgranger.leakwatch.adapter.ConnectivityOwnerResolver
import io.github.yannickgranger.leakwatch.adapter.FileArchiveStore
import io.github.yannickgranger.leakwatch.adapter.PackageAppDirectory
import io.github.yannickgranger.leakwatch.adapter.ProtectedSocketFactory
import io.github.yannickgranger.leakwatch.adapter.TunDevice
import io.github.yannickgranger.leakwatch.adapter.UnderlyingDns
import io.github.yannickgranger.leakwatch.adapter.UsageStatsSource
import io.github.yannickgranger.leakwatch.adapter.WallClock
import io.github.yannickgranger.leakwatch.domain.AppStateClassifier
import io.github.yannickgranger.leakwatch.domain.AppSummary
import io.github.yannickgranger.leakwatch.domain.ArchiveWriter
import io.github.yannickgranger.leakwatch.domain.Attribution
import io.github.yannickgranger.leakwatch.domain.EngineConfig
import io.github.yannickgranger.leakwatch.domain.RelayEngine
import io.github.yannickgranger.leakwatch.domain.TrackerMatcher
import io.github.yannickgranger.leakwatch.domain.WgLink

class LeakWatchVpnService : VpnService() {
    private val main = Handler(Looper.getMainLooper())
    private var tun: TunDevice? = null
    private var engine: RelayEngine? = null
    private var thread: Thread? = null
    private var lastNotify = 0L
    private var link: WgLink? = null
    private var reports: ScheduledExecutorService? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                Capture.setWanted(this, false)
                stopCapture()
                return START_NOT_STICKY
            }
            else -> startCapture()
        }
        return START_STICKY
    }

    override fun onRevoke() {
        Capture.setWanted(this, false)
        stopCapture()
    }

    override fun onDestroy() {
        stopCapture()
        super.onDestroy()
    }

    private fun startCapture() {
        goForeground(notification(0, 0))
        if (engine != null) return
        val cm = getSystemService(ConnectivityManager::class.java)
        val upstream = UnderlyingDns.resolver(cm)
        val wg = if (!BuildConfig.WIREGUARD) null else runCatching { WireGuardLink.config(this)?.let { WireGuardLink.link(it)?.let { l -> it to l } } }.getOrNull()
        val pfd = try {
            val builder = Builder()
                .setSession("LeakWatch")
                .addAddress("10.111.0.1", 32)
                .addAddress("fd00:111::1", 128)
            wg?.first?.addresses?.forEach { builder.addAddress(it.address, it.prefix) }
            builder
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(DNS)
                .setMtu(1500)
                .addDisallowedApplication(packageName)
                .setBlocking(false)
                .setConfigureIntent(openApp())
                .establish()
        } catch (e: Exception) {
            null
        }
        if (pfd == null) {
            finish()
            return
        }
        val device = TunDevice(pfd)
        val clock = WallClock
        val archive = ArchiveWriter(FileArchiveStore(Capture.archiveRoot(this)), clock)
        archive.loadToday()
        val trackers = runCatching { TrackerMatcher.parse(assets.open("trackers.txt").bufferedReader().readText()) }.getOrElse { TrackerMatcher(emptyList()) }
        val relay = RelayEngine(
            source = device,
            sink = device,
            sockets = ProtectedSocketFactory(this),
            attribution = Attribution(ConnectivityOwnerResolver(cm), PackageAppDirectory(packageManager)),
            blocks = Capture.blocks(this),
            trackers = trackers,
            archive = archive,
            clock = clock,
            config = EngineConfig(InetAddress.getByName(DNS), InetSocketAddress(upstream, 53)),
            stats = { apps -> onStats(apps) },
            appStates = AppStateClassifier(UsageStatsSource(this), clock),
            tunnel = wg?.second,
            domains = Capture.domains(this),
        )
        link = wg?.second
        Capture.setWanted(this, true)
        val report = Capture.report(this)
        val blocks = Capture.blocks(this)
        reports = Executors.newSingleThreadScheduledExecutor().also {
            it.scheduleWithFixedDelay({ runCatching { Capture.publishOffenders(report.write(blocks.blocked())) } }, 0, OFFENDERS_MINUTES, TimeUnit.MINUTES)
        }
        tun = device
        engine = relay
        thread = Thread({ relay.run() }, "leakwatch-relay").also { it.start() }
        Capture.stopAction = { stopCapture() }
        Capture.setRunning(true)
    }

    private fun onStats(apps: List<AppSummary>) {
        Capture.publish(apps)
        WireGuardLink.publishHandshake(link?.peer?.lastHandshakeMs)
        val now = System.currentTimeMillis()
        if (now - lastNotify < 5_000) return
        lastNotify = now
        val flows = apps.sumOf { it.flows }
        val out = apps.sumOf { it.bytesOut }
        main.post { if (engine != null) getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(flows, out)) }
    }

    private fun stopCapture() {
        val relay = engine
        val worker = thread
        val device = tun
        val scheduled = reports
        engine = null
        thread = null
        tun = null
        link = null
        reports = null
        Capture.stopAction = null
        if (relay == null) {
            finish()
            return
        }
        relay.stop()
        worker?.join(4_000)
        device?.close()
        WireGuardLink.publishHandshake(null)
        scheduled?.shutdownNow()
        val report = Capture.report(this)
        val blocks = Capture.blocks(this)
        Thread({ runCatching { Capture.publishOffenders(report.write(blocks.blocked())) } }, "leakwatch-offenders").start()
        Capture.setRunning(false)
        finish()
    }

    private fun finish() {
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun openApp(): PendingIntent =
        PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)

    private fun notification(flows: Int, bytesOut: Long): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (nm.getNotificationChannel(CHANNEL) == null) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.channel_capture), NotificationManager.IMPORTANCE_LOW))
        }
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_watch)
            .setContentTitle(getString(R.string.notify_title))
            .setContentText(getString(R.string.notify_text, flows, Format.bytes(bytesOut)))
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openApp())
            .build()
    }

    private fun goForeground(n: Notification) {
        if (Build.VERSION.SDK_INT >= 34) {
            try {
                startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } catch (e: Exception) {
                startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            }
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
    }

    companion object {
        const val ACTION_START = "io.github.yannickgranger.leakwatch.START"
        const val ACTION_STOP = "io.github.yannickgranger.leakwatch.STOP"
        private const val DNS = "10.111.0.2"
        private const val CHANNEL = "capture"
        private const val NOTIFICATION_ID = 1
        private const val OFFENDERS_MINUTES = 5L
    }
}
