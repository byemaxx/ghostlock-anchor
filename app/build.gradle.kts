plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

val generatedJniLibs = layout.buildDirectory.dir("generated/jniLibs")
val anchorNativeOutput = generatedJniLibs.map { it.file("arm64-v8a/libanchor.so") }
val anchorNativeBuilder = rootProject.file("tools/build_anchor_native.py")
val anchorNativeSource = rootProject.file("ghostlock-oneplus")
val configuredPython = providers.gradleProperty("pythonExecutable")
    .orElse(providers.environmentVariable("PYTHON"))
    .orElse("${System.getProperty("user.home")}/miniconda3/envs/py14/python.exe")

val buildAnchorNative by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the current GhostLock helper for APK packaging."
    inputs.dir(anchorNativeSource.resolve("src"))
    inputs.file(anchorNativeSource.resolve("Makefile"))
    inputs.file(anchorNativeBuilder)
    outputs.file(anchorNativeOutput)
    commandLine(
        configuredPython.get(),
        anchorNativeBuilder.absolutePath,
        "--project-dir", rootProject.projectDir.absolutePath,
        "--source-dir", anchorNativeSource.absolutePath,
        "--output", anchorNativeOutput.get().asFile.absolutePath,
    )
}

android {
    namespace = "com.anchor.bootstrap"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.anchor.bootstrap"
        minSdk = 33
        targetSdk = 36
        versionCode = 4
        versionName = "1.2"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = false
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    sourceSets {
        getByName("main").jniLibs.directories.apply {
            clear()
            add(generatedJniLibs.get().asFile.absolutePath)
        }
    }
    // The bootstrap helper is launched through ProcessBuilder rather than loaded through
    // System.loadLibrary. Keep the JNI executable extracted at
    // ApplicationInfo.nativeLibraryDir on Android 15/16.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

tasks.matching {
    it.name.startsWith("merge") && it.name.endsWith("JniLibFolders")
}.configureEach {
    dependsOn(buildAnchorNative)
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    testImplementation(libs.junit)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
