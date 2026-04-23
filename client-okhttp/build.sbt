scalaVersion := "2.12.20"
organization := "morbid"
name         := "morbid-client-okhttp"
version      := "v1.1.0-SNAPSHOT"

libraryDependencies ++= Seq(
  "com.squareup.okhttp3" % "okhttp"       % "4.12.0",
  "com.fasterxml.jackson.core"    % "jackson-databind"       % "2.17.0",
  "com.fasterxml.jackson.module" %% "jackson-module-scala"   % "2.17.0",
  "com.fasterxml.jackson.datatype" % "jackson-datatype-jdk8" % "2.17.0",
  "com.fasterxml.jackson.datatype" % "jackson-datatype-jsr310" % "2.17.0",
  "io.jsonwebtoken" % "jjwt-api"     % "0.12.3",
  "io.jsonwebtoken" % "jjwt-impl"    % "0.12.3" % Runtime,
  "io.jsonwebtoken" % "jjwt-jackson" % "0.12.3" % Runtime,
  "org.slf4j"       % "slf4j-api"    % "2.0.12"
)

resolvers += Resolver.mavenLocal
