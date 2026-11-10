package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.port.DomainRuleStore

enum class RuleAction { BLOCK, ALLOW }

data class DomainRule(val scope: String, val pattern: String, val action: RuleAction) {
    val global: Boolean get() = scope == ALL

    companion object {
        const val ALL = "all"
    }
}

object DomainPattern {
    fun normalize(s: String): String = s.trim().trimEnd('.').lowercase()

    fun matches(pattern: String, host: String?): Boolean {
        if (host == null) return false
        val p = normalize(pattern)
        val h = normalize(host)
        if (p.isEmpty() || h.isEmpty()) return false
        if (p.startsWith("*.")) {
            val base = p.substring(2).split('.')
            val labels = h.split('.')
            return labels.size >= base.size && labelsMatch(base, labels.takeLast(base.size))
        }
        val labels = h.split('.')
        val parts = p.split('.')
        return parts.size == labels.size && labelsMatch(parts, labels)
    }

    private fun labelsMatch(pattern: List<String>, labels: List<String>): Boolean =
        pattern.indices.all { label(pattern[it], labels[it]) }

    private fun label(pattern: String, label: String): Boolean {
        if (!pattern.contains('*')) return pattern == label
        val pieces = pattern.split('*')
        if (!label.startsWith(pieces.first())) return false
        var at = pieces.first().length
        for (k in 1 until pieces.size - 1) {
            val found = label.indexOf(pieces[k], at)
            if (found < 0) return false
            at = found + pieces[k].length
        }
        val last = pieces.last()
        return label.length - last.length >= at && label.endsWith(last)
    }
}

object DomainRules {
    fun encode(rules: List<DomainRule>): String =
        rules.joinToString("") { "${it.scope}\t${it.action.name.lowercase()}\t${it.pattern}\n" }

    fun decode(text: String): List<DomainRule> = text.lineSequence().mapNotNull { line ->
        val c = line.split('\t')
        if (c.size != 3 || c[0].isBlank() || c[2].isBlank()) return@mapNotNull null
        val action = when (c[1]) {
            "block" -> RuleAction.BLOCK
            "allow" -> RuleAction.ALLOW
            else -> return@mapNotNull null
        }
        DomainRule(c[0], DomainPattern.normalize(c[2]), action)
    }.toList()

    fun defaults(text: String): List<DomainRule> =
        text.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.map { DomainRule(DomainRule.ALL, DomainPattern.normalize(it), RuleAction.BLOCK) }.toList()
}

class DomainPolicy(private val store: DomainRuleStore, private val defaults: List<DomainRule>) {
    @Volatile
    private var current: List<DomainRule> = load()

    private fun load(): List<DomainRule> {
        val saved = runCatching { store.load() }.getOrNull()
        if (saved != null) return DomainRules.decode(saved)
        runCatching { store.save(DomainRules.encode(defaults)) }
        return defaults
    }

    fun rules(): List<DomainRule> = current

    fun isBlocked(host: String?, packages: List<String>): Boolean {
        if (host == null) return false
        val hits = current.filter { (it.global || it.scope in packages) && DomainPattern.matches(it.pattern, host) }
        if (hits.isEmpty()) return false
        val scoped = hits.filterNot { it.global }
        if (scoped.any { it.action == RuleAction.ALLOW }) return false
        if (scoped.any { it.action == RuleAction.BLOCK }) return true
        if (hits.any { it.action == RuleAction.ALLOW }) return false
        return true
    }

    @Synchronized
    fun put(rule: DomainRule) {
        val r = rule.copy(pattern = DomainPattern.normalize(rule.pattern))
        if (r.pattern.isEmpty() || r.scope.isBlank()) return
        save(current.filterNot { it.scope == r.scope && it.pattern == r.pattern } + r)
    }

    @Synchronized
    fun remove(scope: String, pattern: String) {
        val p = DomainPattern.normalize(pattern)
        save(current.filterNot { it.scope == scope && it.pattern == p })
    }

    @Synchronized
    fun restoreDefaults() {
        save(current.filterNot { c -> defaults.any { it.scope == c.scope && it.pattern == c.pattern } } + defaults)
    }

    private fun save(rules: List<DomainRule>) {
        current = rules
        runCatching { store.save(DomainRules.encode(rules)) }
    }
}
