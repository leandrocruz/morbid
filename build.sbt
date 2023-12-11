organization                 := "morbid"
name                         := "morbid-server"
version                      := "v0.0.1-SNAPSHOT"
Docker / version             := version.value
doc / sources                := Seq.empty
packageDoc / publishArtifact := false
topLevelDirectory            := None
executableScriptName         := "run"
Universal / packageName      := "package"
Compile / run / mainClass    := Option("morbid.MorbidServer")
resolvers                    += Resolver.mavenLocal
testFrameworks               += new TestFramework("zio.test.sbt.ZTestFramework")
libraryDependencies          ++= Seq(
  "guara"                %% "guara-framework"   % "v0.0.2-SNAPSHOT" changing(),
  "com.github.pathikrit" %% "better-files"      % "3.9.2",
  "io.jsonwebtoken"      % "jjwt-api"           % "0.12.3",
  "io.jsonwebtoken"      % "jjwt-impl"          % "0.12.3",
  "io.jsonwebtoken"      % "jjwt-jackson"       % "0.12.3",
  "io.scalaland"         %% "chimney"           % "0.8.2",
  "com.google.firebase"  %  "firebase-admin"    % "9.1.1",
  "io.getquill"          %% "quill-zio"         % "4.8.0",
  "io.getquill"          %% "quill-jdbc-zio"    % "4.8.0",
  "dev.zio"              %% "zio-optics"        % "0.2.1",
  "org.postgresql"       %  "postgresql"        % "42.5.4",
  "dev.zio"              %% "zio-test"          % "2.0.19" % Test,
  "dev.zio"              %% "zio-test-sbt"      % "2.0.19" % Test,
  "dev.zio"              %% "zio-test-magnolia" % "2.0.19" % Test
)

lazy val root = (project in file("."))
  .enablePlugins(JavaAppPackaging)
  .settings(BuildHelper.stdSettings)
