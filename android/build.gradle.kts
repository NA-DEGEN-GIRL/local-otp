// Kotlin comes with AGP (built-in Kotlin); the Compose compiler plugin is
// pinned to the matching Kotlin version.
plugins {
    id("com.android.application") version "9.5.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.21" apply false
}
