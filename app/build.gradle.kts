plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

val wireGuard = providers.gradleProperty("leakwatch.wireguard").map { it.toBoolean() }.getOrElse(false)

android {
    namespace = "io.github.yannickgranger.leakwatch"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.yannickgranger.leakwatch"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
        buildConfigField("boolean", "WIREGUARD", wireGuard.toString())
        manifestPlaceholders["wireguardImport"] = wireGuard.toString()
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    androidResources {
        localeFilters += listOf("en")
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.all {
            it.systemProperty("wg.it", System.getProperty("wg.it") ?: "")
            it.testLogging { events("passed", "skipped", "failed") }
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
}
