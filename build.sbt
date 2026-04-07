lazy val types = (project in file("types"))
  .withId("morbid-types")
  .settings(
    BuildHelper.stdSettings,
    libraryDependencies := BuildHelper.typesDependencies
  )

lazy val commons = (project in file("commons"))
  .withId("morbid-commons")
  .dependsOn(types)
  .settings(
    BuildHelper.stdSettings,
    libraryDependencies := BuildHelper.commonsDependencies
  )

lazy val client = (project in file("client"))
  .withId("morbid-client")
  .dependsOn(commons)
  .settings(
    BuildHelper.stdSettings,
    libraryDependencies := BuildHelper.clientDependencies
  )

lazy val legacy = (project in file("legacy"))
  .withId("morbid-legacy-client")
  .dependsOn(commons)
  .settings(
    BuildHelper.stdSettings,
    libraryDependencies := BuildHelper.clientDependencies
  )

lazy val root = (project in file("server"))
  .withId("morbid-server")
  .dependsOn(commons, legacy)
  .enablePlugins(JavaAppPackaging)
  .settings(
    BuildHelper.stdSettings,
    Compile / run / mainClass := Option("morbid.MorbidServer"),
    topLevelDirectory         := None,
    executableScriptName      := "run",
    Universal / packageName   := "package",
    libraryDependencies       := BuildHelper.serverDependencies,
    dependencyOverrides       += "dev.zio" %% "zio-json" % BuildHelper.ZioJsonVersion,
  )
