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

dependencies {
    // Same pin the Android project uses — see FC-AJDK/build.gradle.kts.
    // freecashj transitively supplies BouncyCastle (bcprov-jdk15to18), which
    // provides Argon2BytesGenerator and RIPEMD160Digest. Do NOT add bcprov-jdk18on —
    // it clashes with bcprov-jdk15to18 as duplicate org.bouncycastle.* classes.
    implementation("com.github.nobodyoffc:freecashj:v0.16") {
        exclude(group = "com.google.code.gson", module = "gson")
        exclude(group = "org.json", module = "json")
        exclude(group = "org.slf4j", module = "slf4j-api")
    }
    implementation("com.google.code.gson:gson:2.10.1")
    implementation("org.slf4j:slf4j-api:2.0.9")
    implementation("org.slf4j:slf4j-nop:2.0.9")
}
