package io.github.yannickgranger.leakwatch.domain

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TelemetryNameMatcherTest {
    @Test
    fun matchesTelemetryTokensBeforeTheRegistrableDomain() {
        assertTrue(TelemetryNameMatcher.matches("log.example.com"))
        assertTrue(TelemetryNameMatcher.matches("events-eu.example.com"))
        assertTrue(TelemetryNameMatcher.matches("app-analytics.vendor.net"))
        assertTrue(TelemetryNameMatcher.matches("Metrics.Shop.Example.COM."))
        assertTrue(TelemetryNameMatcher.matches("crash.reports.example.org"))
    }

    @Test
    fun doesNotSplitInsideALabelToken() {
        assertFalse(TelemetryNameMatcher.matches("firebaselogging-pa.googleapis.com"))
        assertFalse(TelemetryNameMatcher.matches("blog.example.com"))
        assertFalse(TelemetryNameMatcher.matches("catalog.shop.com"))
    }

    @Test
    fun ignoresTheRegistrableDomainItself() {
        assertFalse(TelemetryNameMatcher.matches("analytics.com"))
        assertFalse(TelemetryNameMatcher.matches("www.analytics.com"))
        assertFalse(TelemetryNameMatcher.matches("stats.co.uk"))
        assertTrue(TelemetryNameMatcher.matches("stats.shop.co.uk"))
    }

    @Test
    fun ignoresAddressesAndBlanks() {
        assertFalse(TelemetryNameMatcher.matches(null))
        assertFalse(TelemetryNameMatcher.matches(""))
        assertFalse(TelemetryNameMatcher.matches("192.0.2.76"))
        assertFalse(TelemetryNameMatcher.matches("2001:db8::1"))
    }
}
