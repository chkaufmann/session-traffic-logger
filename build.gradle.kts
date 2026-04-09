plugins {
    kotlin("jvm") version "2.0.21"
}

group = "trafficlogger"
version = "v1.0"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.2")
    implementation("org.xerial:sqlite-jdbc:3.47.1.0")
}

kotlin {
    jvmToolchain(20)
}

tasks.jar {
    archiveFileName.set("session-traffic-logger.jar")
    
    // Alle dependencies ins JAR einpacken (Fat JAR)
    from(configurations.runtimeClasspath.get().map {
        if (it.isDirectory) it else zipTree(it)
    })
    
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    manifest {
        attributes["Implementation-Title"] = "Traffic Logger"
        attributes["Implementation-Version"] = version
    }
}