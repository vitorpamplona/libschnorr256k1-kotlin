plugins {
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.androidKotlinMultiplatformLibrary) apply false
    alias(libs.plugins.vanniktech.mavenPublish) apply false
    alias(libs.plugins.diffplugSpotless)
}

allprojects {
    apply(plugin = "com.diffplug.spotless")

    spotless {
        kotlin {
            target("src/**/*.kt")

            // Same ktlint and header as Quartz, Amethyst and crypto-kmp, so a file moved between
            // the repos formats identically on every side.
            ktlint("1.7.1")
            licenseHeaderFile(
                rootProject.file("spotless/copyright.kt"),
                "@file:|package|import|class|object|sealed|open|interface|abstract ",
            )
        }
    }
}
