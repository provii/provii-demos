// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    id("io.gitlab.arturbosch.detekt") version "1.23.8"
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

subprojects {
    plugins.withId("io.gitlab.arturbosch.detekt") {
        extensions.configure<io.gitlab.arturbosch.detekt.extensions.DetektExtension> {
            config.setFrom(files("${rootProject.projectDir}/detekt.yml"))
            buildUponDefaultConfig = true
        }
    }
}
