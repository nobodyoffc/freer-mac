plugins {
    application
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

application {
    mainClass.set("cash.freer.mac.vectorgen.VectorGen")
}

// External jars shared by the generator itself and by the FC-AJDK
// compilation below. Kept in its own configuration so `compileFcAjdk`
// can use a classpath that does NOT contain its own output — depending
// on `runtimeClasspath` there is a dependency cycle.
val externalDeps: Configuration by configurations.creating
configurations["implementation"].extendsFrom(externalDeps)

dependencies {
    // Same pin the Android project uses — see FC-AJDK/build.gradle.kts.
    // freecashj transitively supplies BouncyCastle (bcprov-jdk15to18), which
    // provides Argon2BytesGenerator and RIPEMD160Digest. Do NOT add bcprov-jdk18on —
    // it clashes with bcprov-jdk15to18 as duplicate org.bouncycastle.* classes.
    externalDeps("com.github.nobodyoffc:freecashj:v0.16") {
        exclude(group = "com.google.code.gson", module = "gson")
        exclude(group = "org.json", module = "json")
        exclude(group = "org.slf4j", module = "slf4j-api")
    }
    externalDeps("com.google.code.gson:gson:2.10.1")
    externalDeps("org.slf4j:slf4j-api:2.0.9")
    externalDeps("org.slf4j:slf4j-nop:2.0.9")
}

// ---------------------------------------------------------------------------
// Phase 8.4.2: compile the REAL FC-AJDK cipher classes on a plain JVM.
//
// The DISK cipher-file vectors must come from the code the Android app
// actually runs, not from a re-implementation of it here — otherwise the
// Swift port would be checked against our own guess at the format.
//
// FC-AJDK is an Android library, but only a handful of its 324 files touch
// the Android SDK and none of them are on the cipher path. We compile just
// the three entry points and let javac pull in the reachable closure via
// -sourcepath (~77 classes); `src/androidstubs/java` sits FIRST on that
// sourcepath so its TimberLogger shadows FC-AJDK's, which would otherwise
// drag in android.util.Log.
// ---------------------------------------------------------------------------

val fcAjdkRoot = file(providers.gradleProperty("fcAjdkSrc")
    .getOrElse("/Users/liuchangyong/AndroidStudioProjects/Freer/FC-AJDK/src/main/java"))
val androidStubs = file("src/androidstubs/java")
val fcAjdkClassesDir = layout.buildDirectory.dir("fcajdk-classes")

val compileFcAjdk by tasks.registering(JavaCompile::class) {
    description = "Compiles the FC-AJDK crypto closure against plain-JVM stubs."
    onlyIf {
        val present = fcAjdkRoot.isDirectory
        if (!present) {
            logger.lifecycle("FC-AJDK sources not found at $fcAjdkRoot — skipping " +
                "(pass -PfcAjdkSrc=/path/to/FC-AJDK/src/main/java to regenerate DISK cipher vectors).")
        }
        present
    }
    source = fileTree(fcAjdkRoot) {
        include("com/fc/fc_ajdk/core/crypto/Encryptor.java")
        include("com/fc/fc_ajdk/core/crypto/Decryptor.java")
        include("com/fc/fc_ajdk/core/crypto/CryptoDataByte.java")
        include("com/fc/fc_ajdk/data/fcData/Hat.java")
        include("com/fc/fc_ajdk/data/feipData/Mail.java")
    }
    classpath = externalDeps
    destinationDirectory.set(fcAjdkClassesDir)
    options.sourcepath = files(androidStubs, fcAjdkRoot)
    options.isWarnings = false
    options.compilerArgs.addAll(listOf("-nowarn", "-Xlint:none"))
    javaCompiler.set(javaToolchains.compilerFor {
        languageVersion.set(JavaLanguageVersion.of(17))
    })
}

dependencies {
    implementation(files(fcAjdkClassesDir) { builtBy(compileFcAjdk) })
}
