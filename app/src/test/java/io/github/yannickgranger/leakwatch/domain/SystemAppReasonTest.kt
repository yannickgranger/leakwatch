package io.github.yannickgranger.leakwatch.domain

import io.github.yannickgranger.leakwatch.port.AppDirectory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemAppReasonTest {
    private val apps = object : AppDirectory {
        override fun packagesForUid(uid: Int) = if (uid == 10050) listOf("com.samsung.android.app") else listOf("com.user.app")
        override fun label(packageName: String) = packageName
        override fun isSystem(packageName: String) = packageName.startsWith("com.samsung.")
    }
    private val attribution = Attribution({ _, _, _ -> -1 }, apps)

    private fun reasons(identity: AppIdentity) =
        Suspicion.reasons(false, false, AppState.FOREGROUND, true, false, 100, 1000, system = identity.system)

    @Test
    fun systemPackageIsMarkedThroughAppDirectory() {
        assertTrue(attribution.forUid(10050).system)
        assertFalse(attribution.forUid(10200).system)
    }

    @Test
    fun notUsedTodayNeverFiresForSystemPackages() {
        assertEquals(emptyList<String>(), reasons(attribution.forUid(10050)))
    }

    @Test
    fun notUsedTodayStillFiresForUserApps() {
        assertEquals(listOf(Suspicion.NOT_USED_TODAY), reasons(attribution.forUid(10200)))
    }

    @Test
    fun systemPackageKeepsItsOtherReasons() {
        assertEquals(listOf(Suspicion.TRACKER), Suspicion.reasons(true, false, AppState.FOREGROUND, true, false, 100, 1000, system = true))
    }
}
