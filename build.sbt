lazy val commons = (project in file("commons"))
  .withId("morbid-commons")
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
    libraryDependencies       := BuildHelper.allDependencies
  )
