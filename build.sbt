lazy val commons = (project in file("commons"))
  .withId("morbid-commons")
  .settings(
    BuildHelper.stdSettings,
    libraryDependencies := BuildHelper.allDependencies
  )

lazy val root = (project in file("server"))
  .withId("morbid-server")
  .dependsOn(commons)
  .enablePlugins(JavaAppPackaging)
  .settings(
    BuildHelper.stdSettings,
    Compile / run / mainClass := Option("morbid.MorbidServer"),
    topLevelDirectory         := None,
    executableScriptName      := "run",
    Universal / packageName   := "package",
    libraryDependencies       := BuildHelper.allDependencies
  )
