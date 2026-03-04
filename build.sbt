import org.scalajs.linker.interface.{ESVersion, ModuleSplitStyle}

lazy val commons = crossProject(JVMPlatform, JSPlatform)
  .crossType(CrossType.Full)
  .in(file("commons"))
  .settings(
    name := "morbid-commons",
    BuildHelper.stdSettings,
    libraryDependencies ++= Seq(
      "dev.zio" %%% "zio-json" % BuildHelper.ZioJsonVersion,
    )
  )
  .jvmSettings(
    libraryDependencies ++= Seq(
      "dev.zio"      %% "zio"             % BuildHelper.ZioVersion,
      "dev.zio"      %% "zio-optics"      % "0.2.2",
      "guara"        %% "guara-framework" % "v1.1.13",
      "io.scalaland" %% "chimney"         % "1.3.0",
    )
  )
  .jsSettings(
    fork := false,
    libraryDependencies ++= Seq(
      "io.github.cquiroz" %%% "scala-java-time"      % "2.5.0",
      "io.github.cquiroz" %%% "scala-java-time-tzdb"  % "2.5.0",
    )
  )

lazy val client = (project in file("client"))
  .settings(
    name := "morbid-client",
    BuildHelper.stdSettings,
    libraryDependencies := BuildHelper.clientDependencies
  )
  .dependsOn(commons.jvm)

lazy val legacy = (project in file("legacy"))
  .settings(
    name := "morbid-legacy-client",
    BuildHelper.stdSettings,
    libraryDependencies := BuildHelper.clientDependencies
  )
  .dependsOn(commons.jvm)

lazy val admin = project.in(file("admin"))
  .enablePlugins(ScalaJSPlugin)
  .dependsOn(commons.js)
  .settings(
    name                            := "morbid-admin",
    fork                            := false,
    BuildHelper.stdSettings,
    scalacOptions                   += "-Wconf:msg=match may not be exhaustive:e",
    scalaJSUseMainModuleInitializer := true,
    scalaJSLinkerConfig ~= {
      _ .withESFeatures(_.withESVersion(ESVersion.ES2018))
        .withModuleKind(ModuleKind.ESModule)
        .withSourceMap(true)
        .withModuleSplitStyle(
          ModuleSplitStyle.SmallModulesFor(List("morbid.admin"))
        )
    },
    libraryDependencies ++= Seq(
      "leandrocruz"       %%% "medulla-framework"     % BuildHelper.MedullaVersion changing(),
      "io.github.cquiroz" %%% "scala-java-time"       % "2.5.0",
      "io.github.cquiroz" %%% "scala-java-time-tzdb"  % "2.5.0",
    )
  )

lazy val root = (project in file("server"))
  .dependsOn(commons.jvm, legacy)
  .enablePlugins(JavaAppPackaging)
  .settings(
    name                          := "morbid-server",
    BuildHelper.stdSettings,
    Compile / run / mainClass     := Option("morbid.MorbidServer"),
    topLevelDirectory             := None,
    executableScriptName          := "run",
    Universal / packageName       := "package",
    libraryDependencies           := BuildHelper.serverDependencies
  )
