package io.github.yannickgranger.leakwatch.domain

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DomainPolicyTest {
    private fun policy(vararg rules: DomainRule, store: MemoryRuleStore = MemoryRuleStore("")): DomainPolicy {
        val p = DomainPolicy(store, emptyList())
        rules.forEach { p.put(it) }
        return p
    }

    private fun block(pattern: String, scope: String = DomainRule.ALL) = DomainRule(scope, pattern, RuleAction.BLOCK)
    private fun allow(pattern: String, scope: String = DomainRule.ALL) = DomainRule(scope, pattern, RuleAction.ALLOW)
    private val app = listOf("com.chatty.app")

    @Test
    fun exactPatternMatchesOnlyThatHost() {
        assertTrue(DomainPattern.matches("s.youtube.com", "s.youtube.com"))
        assertFalse(DomainPattern.matches("s.youtube.com", "x.s.youtube.com"))
        assertFalse(DomainPattern.matches("s.youtube.com", "youtube.com"))
        assertFalse(DomainPattern.matches("s.youtube.com", "ss.youtube.com"))
    }

    @Test
    fun suffixPatternMatchesDomainAndEverySubdomain() {
        assertTrue(DomainPattern.matches("*.appsflyersdk.com", "appsflyersdk.com"))
        assertTrue(DomainPattern.matches("*.appsflyersdk.com", "inapps.appsflyersdk.com"))
        assertTrue(DomainPattern.matches("*.appsflyersdk.com", "a.b.appsflyersdk.com"))
        assertFalse(DomainPattern.matches("*.appsflyersdk.com", "notappsflyersdk.com"))
        assertFalse(DomainPattern.matches("*.appsflyersdk.com", "appsflyersdk.com.evil.net"))
    }

    @Test
    fun oneLabelWildcardDoesNotCrossDots() {
        val p = "browser-intake-*.datadoghq.com"
        assertTrue(DomainPattern.matches(p, "browser-intake-us5-datadoghq.datadoghq.com"))
        assertTrue(DomainPattern.matches(p, "browser-intake-.datadoghq.com"))
        assertFalse(DomainPattern.matches(p, "browser-intake-us5.eu.datadoghq.com"))
        assertFalse(DomainPattern.matches(p, "x.browser-intake-us5.datadoghq.com"))
        assertFalse(DomainPattern.matches(p, "browser-intake-datadoghq.com"))
        assertFalse(DomainPattern.matches("a*b.example.com", "a.x.b.example.com"))
        assertTrue(DomainPattern.matches("a*b.example.com", "axxb.example.com"))
    }

    @Test
    fun caseAndTrailingDotAreIgnored() {
        assertTrue(DomainPattern.matches("Graph.Facebook.com.", "GRAPH.facebook.COM"))
        assertTrue(DomainPattern.matches("graph.facebook.com", "graph.facebook.com."))
        assertTrue(DomainPattern.matches("*.APP-measurement.com", "Region1.App-Measurement.com."))
    }

    @Test
    fun globalBlockBlocksEveryApp() {
        val p = policy(block("graph.facebook.com"))
        assertTrue(p.isBlocked("graph.facebook.com", app))
        assertTrue(p.isBlocked("graph.facebook.com", emptyList()))
        assertFalse(p.isBlocked("www.facebook.com", app))
        assertFalse(p.isBlocked(null, app))
    }

    @Test
    fun noRuleMeansNotBlocked() {
        assertFalse(policy().isBlocked("example.com", app))
    }

    @Test
    fun globalAllowBeatsGlobalBlock() {
        val p = policy(block("*.example.com"), allow("api.example.com"))
        assertFalse(p.isBlocked("api.example.com", app))
        assertTrue(p.isBlocked("ads.example.com", app))
    }

    @Test
    fun packageBlockBeatsGlobalAllow() {
        val p = policy(allow("api.example.com"), block("api.example.com", "com.chatty.app"))
        assertTrue(p.isBlocked("api.example.com", app))
        assertFalse(p.isBlocked("api.example.com", listOf("com.other.app")))
    }

    @Test
    fun packageBlockOnlyHitsThatPackage() {
        val p = policy(block("t.example.com", "com.chatty.app"))
        assertTrue(p.isBlocked("t.example.com", listOf("com.shared.one", "com.chatty.app")))
        assertFalse(p.isBlocked("t.example.com", listOf("com.other.app")))
    }

    @Test
    fun packageAllowBeatsPackageBlock() {
        val p = policy(block("*.example.com", "com.chatty.app"), allow("cdn.example.com", "com.chatty.app"))
        assertFalse(p.isBlocked("cdn.example.com", app))
        assertTrue(p.isBlocked("ads.example.com", app))
    }

    @Test
    fun packageAllowBeatsGlobalBlock() {
        val p = policy(block("s.youtube.com"), allow("s.youtube.com", "com.chatty.app"))
        assertFalse(p.isBlocked("s.youtube.com", app))
        assertTrue(p.isBlocked("s.youtube.com", listOf("com.other.app")))
    }

    @Test
    fun defaultsLoadOnFirstRunAndRulesPersist() {
        val store = MemoryRuleStore()
        val first = DomainPolicy(store, DomainRules.defaults("graph.facebook.com\n*.appsflyersdk.com\n"))
        assertTrue(first.isBlocked("graph.facebook.com", app))
        first.remove(DomainRule.ALL, "graph.facebook.com")
        first.put(block("x.example.com", "com.chatty.app"))
        val again = DomainPolicy(store, DomainRules.defaults("graph.facebook.com\n*.appsflyersdk.com\n"))
        assertFalse(again.isBlocked("graph.facebook.com", app))
        assertTrue(again.isBlocked("x.example.com", app))
        assertTrue(again.isBlocked("t.appsflyersdk.com", app))
        again.restoreDefaults()
        assertTrue(again.isBlocked("graph.facebook.com", app))
        assertTrue(again.isBlocked("x.example.com", app))
    }

    @Test
    fun putReplacesTheRuleOfTheSameScopeAndPattern() {
        val p = policy(block("a.example.com"))
        p.put(allow("a.example.com"))
        assertEquals(listOf(allow("a.example.com")), p.rules())
    }

    @Test
    fun shippedDefaultsAreExactlyTheEighteenPatterns() {
        val text = java.io.File("src/main/assets/blocklist-default.txt").readText()
        val rules = DomainRules.defaults(text)
        assertEquals(18, rules.size)
        assertTrue(rules.all { it.global && it.action == RuleAction.BLOCK })
        val p = DomainPolicy(MemoryRuleStore(), rules)
        for (h in listOf("inapps.appsflyersdk.com", "graph.facebook.com", "browser-intake-us5-datadoghq.datadoghq.com", "s.youtube.com", "mads.amazon.com")) {
            assertTrue(h, p.isBlocked(h, app))
        }
        for (h in listOf("firebaseinstallations.googleapis.com", "firebaseremoteconfig.googleapis.com", "play.googleapis.com", "youtubei.googleapis.com", "rr1.googlevideo.com", "ondevicesafety-pa.googleapis.com")) {
            assertFalse(h, p.isBlocked(h, app))
        }
    }
}
