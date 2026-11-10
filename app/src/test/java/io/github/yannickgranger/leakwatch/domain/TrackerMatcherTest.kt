package io.github.yannickgranger.leakwatch.domain

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrackerMatcherTest {
    private val m = TrackerMatcher(listOf("doubleclick.net", "app-measurement.com", "graph.facebook.com"))

    @Test
    fun matchesExactAndSubdomains() {
        assertTrue(m.matches("doubleclick.net"))
        assertTrue(m.matches("ad.doubleclick.net"))
        assertTrue(m.matches("graph.facebook.com"))
        assertFalse(m.matches("facebook.com"))
    }

    @Test
    fun respectsLabelBoundary() {
        assertFalse(m.matches("notdoubleclick.net"))
        assertFalse(m.matches("doubleclick.net.evil.org"))
    }

    @Test
    fun ignoresCaseAndTrailingDot() {
        assertTrue(m.matches("SSL.App-Measurement.com."))
        assertTrue(m.matches("Ad.DoubleClick.NET."))
    }

    @Test
    fun nullAndBlankNeverMatch() {
        assertFalse(m.matches(null))
        assertFalse(m.matches(""))
    }

    @Test
    fun bundledListHasAtLeast80KnownTrackers() {
        val text = File("src/main/assets/trackers.txt").readText()
        val bundled = TrackerMatcher.parse(text)
        assertTrue(bundled.size >= 80)
        for (h in listOf("doubleclick.net", "www.google-analytics.com", "app-measurement.com", "graph.facebook.com", "t.appsflyer.com", "app.adjust.com", "api2.branch.io", "settings.crashlytics.com", "firebaselogging-pa.googleapis.com", "o1.ingest.sentry.io", "api.amplitude.com", "api.mixpanel.com", "api.onesignal.com", "config.samsungads.com", "log-upload.tiktokv.com", "static.criteo.com", "cdn.taboola.com")) {
            assertTrue(h, bundled.matches(h))
        }
        assertFalse(bundled.matches("example.com"))
        assertFalse(bundled.matches("neverssl.com"))
    }

    @Test
    fun firebaseLoggingHostIsTracker() {
        val text = File("src/main/assets/trackers.txt").readText()
        assertTrue(text.lines().count { it.isNotBlank() } >= 100)
        val bundled = TrackerMatcher.parse(text)
        for (h in listOf(
            "firebaselogging.googleapis.com", "firebaselogging-pa.googleapis.com", "firebase-settings.crashlytics.com",
            "firebaseinstallations.googleapis.com", "crashlyticsreports-pa.googleapis.com", "app-measurement.com",
            "appsgrowthpromo-pa.googleapis.com",
        )) {
            assertTrue(h, bundled.matches(h))
        }
        assertFalse(bundled.matches("www.googleapis.com"))
        assertFalse(bundled.matches("googleapis.com"))
    }

    @Test
    fun harvestDomainsAreTrackers() {
        val bundled = TrackerMatcher.parse(File("src/main/assets/trackers.txt").readText())
        for (h in listOf("browser-intake-us5-datadoghq.datadoghq.com", "api.sprig.com", "device-api.urbanairship.com", "mads.amazon.com", "mads-eu.amazon.com", "s.youtube.com")) {
            assertTrue(h, bundled.matches(h))
        }
    }
}
