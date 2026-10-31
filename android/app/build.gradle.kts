import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The About screen shows the date of the latest security review: the newest docs/security/YYYY-MM-DD.md.
val lastSecurityReview: String = rootProject.file("../docs/security")
    .listFiles { f -> Regex("""\d{4}-\d{2}-\d{2}\.md""").matches(f.name) }
    ?.maxOfOrNull { it.name.removeSuffix(".md") }
    ?: error("No security review found in docs/security")

/** Copies CHANGELOG.md and PRIVACY.md into the APK's assets, so the app shows the same text as the repository. */
abstract class BundleDocs : DefaultTask() {
    @get:InputFiles abstract val docs: ConfigurableFileCollection
    @get:OutputDirectory abstract val out: DirectoryProperty

    @TaskAction fun copy() {
        val dir = out.get().asFile
        dir.deleteRecursively(); dir.mkdirs()
        docs.files.forEach { it.copyTo(File(dir, it.name)) }
    }
}
val bundleDocs = tasks.register<BundleDocs>("bundleDocs") {
    docs.from(rootProject.file("../CHANGELOG.md"), rootProject.file("../PRIVACY.md"))
}

// Release signing: ~/.clipway/keystore.properties (never in the repo).
val signing = File(System.getProperty("user.home"), ".clipway/keystore.properties")
val signingProps = Properties().apply { if (signing.exists()) signing.inputStream().use { load(it) } }

android {
    namespace = "dev.sidali.clipway"
    compileSdk = 36
    defaultConfig {
        applicationId = "dev.sidali.clipway"
        minSdk = 31
        targetSdk = 36
        versionCode = 5
        versionName = "0.3.0"
        buildConfigField("String", "SECURITY_REVIEW", "\"$lastSecurityReview\"")
        // Reference relay; any relay can be set in the app.
        buildConfigField("String", "DEFAULT_RELAY", "\"https://clip.sidali.dev\"")
    }
    signingConfigs {
        if (signing.exists()) create("release") {
            storeFile = file(signingProps.getProperty("storeFile"))
            storePassword = signingProps.getProperty("storePassword")
            keyAlias = signingProps.getProperty("keyAlias")
            keyPassword = signingProps.getProperty("keyPassword")
        }
    }
    buildTypes {
        debug {
            // Debug builds may also talk to a relay on this computer (http://127.0.0.1:7710 through
            // adb reverse, or http://10.0.2.2:7710 from the emulator). Release builds: https only.
            buildConfigField("Boolean", "ALLOW_LOCAL_HTTP", "true")
        }
        release {
            buildConfigField("Boolean", "ALLOW_LOCAL_HTTP", "false")
            // Reproducible builds: no git commit id baked into the APK.
            vcsInfo.include = false
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            // -Punsigned builds an unsigned APK, used to check that a build is reproducible.
            if (!project.hasProperty("unsigned")) signingConfigs.findByName("release")?.let { signingConfig = it }
        }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    buildFeatures { compose = true; buildConfig = true }
    packaging { resources.excludes += "/META-INF/{AL2.0,LGPL2.1}" }
    dependenciesInfo { includeInApk = false; includeInBundle = false }
    // English only: library translations are dropped too, so no screen mixes two languages.
    androidResources { localeFilters += listOf("en") }
    lint { warningsAsErrors = false; abortOnError = true }
}
androidComponents {
    onVariants { v -> v.sources.assets?.addGeneratedSourceDirectory(bundleDocs, BundleDocs::out) }
}
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

dependencies {
    val bom = platform("androidx.compose:compose-bom:2025.09.01")
    implementation(bom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.11.0")
    // The WebSocket to the relay. No other network library, no analytics, no Google services.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // Reads and draws the pairing QR code (core only: the camera is Camera2, no scanning library).
    implementation("com.google.zxing:core:3.5.3")
    // Save and fetch the 12 words in the user's password manager (Android 14 and later).
    implementation("androidx.credentials:credentials:1.5.0")
    testImplementation("junit:junit:4.13.2")
    // Reads docs/VECTORS.json in the JVM tests (org.json is part of Android, not of the JVM).
    testImplementation("org.json:json:20240303")
}
