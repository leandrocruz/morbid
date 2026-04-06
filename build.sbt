lazy val commons = (crossProject(JSPlatform, JVMPlatform) in file("commons"))
  .settings(
    name := "morbid-commons",
    BuildHelper.stdSettings,
    libraryDependencies := Seq(
      "io.scalaland" %%% "chimney"  % "1.9.0",
      "dev.zio"      %%% "zio-json" % BuildHelper.ZioJsonVersion
    )
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      "ch.qos.logback" %  "logback-classic" % "1.5.18",
      "guara"          %% "guara-framework" % "v1.3.0"
    )
  )

lazy val client = (project in file("client"))
  .withId("morbid-client")
  .dependsOn(commons.jvm)
  .settings(
    BuildHelper.stdSettings,
    libraryDependencies := BuildHelper.clientDependencies
  )

lazy val routes = (project in file("routes"))
  .withId("morbid-routes")
  .dependsOn(client)
  .settings(
    BuildHelper.stdSettings,
  )

lazy val legacy = (project in file("legacy"))
  .withId("morbid-legacy-client")
  .dependsOn(commons.jvm)
  .settings(
    BuildHelper.stdSettings,
    libraryDependencies := BuildHelper.clientDependencies
  )

lazy val root = (project in file("server"))
  .withId("morbid-server")
  .dependsOn(commons.jvm, legacy)
  .enablePlugins(JavaAppPackaging)
  .settings(
    BuildHelper.stdSettings,
    Compile / run / mainClass := Option("morbid.MorbidServer"),
    topLevelDirectory         := None,
    executableScriptName      := "run",
    Universal / packageName   := "package",
    libraryDependencies       := BuildHelper.serverDependencies
  )
