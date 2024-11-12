import sbt._
import sbt.Keys._

object BuildHelper {

  val ScalaVersion   = "3.3.3"
  val ZioVersion     = "2.1.6" //same as guara
  val ZioJsonVersion = "0.6.2"    //same as guara

  lazy val dependencies = new {
    val betterFiles     = "com.github.pathikrit" %% "better-files"      % "3.9.2"
    val commonsCodec    = "commons-codec"        %  "commons-codec"     % "1.17.0"
    val commonsLang     = "org.apache.commons"   % "commons-lang3"      % "3.17.0"
    val chimney         = "io.scalaland"         %% "chimney"           % "1.3.0"
    val firebase        = "com.google.firebase"  %  "firebase-admin"    % "9.3.0"
    val guara           = "guara"                %% "guara-framework"   % "v0.1.0-SNAPSHOT" changing()
    val jjwtApi         = "io.jsonwebtoken"      % "jjwt-api"           % "0.12.3"
    val jjwtImpl        = "io.jsonwebtoken"      % "jjwt-impl"          % "0.12.3"
    val jjwtJackson     = "io.jsonwebtoken"      % "jjwt-jackson"       % "0.12.3"
    val quillZio        = "io.getquill"          %% "quill-zio"         % "4.8.5"
    val quillZioJdbc    = "io.getquill"          %% "quill-jdbc-zio"    % "4.8.4"
    val postgresql      = "org.postgresql"       %  "postgresql"        % "42.7.3"
    val scalaCsv        = "com.github.tototoshi" %% "scala-csv"         % "2.0.0"
    val zioOptics       = "dev.zio"              %% "zio-optics"        % "0.2.1"
    val zio             = "dev.zio"              %% "zio"               % ZioVersion
    val zioJson         = "dev.zio"              %% "zio-json"          % ZioJsonVersion
    val zioTest         = "dev.zio"              %% "zio-test"          % ZioVersion % Test
    val zioTestSbt      = "dev.zio"              %% "zio-test-sbt"      % ZioVersion % Test
    val zioTestMagnolia = "dev.zio"              %% "zio-test-magnolia" % ZioVersion % Test
  }

  lazy val commonsDependencies = Seq(
    dependencies.zio,
    dependencies.zioJson,
    dependencies.zioOptics,
    dependencies.guara,
    dependencies.chimney
  )

  lazy val clientDependencies = Seq(
    dependencies.zio,
    dependencies.zioJson,
  )

  lazy val allDependencies = Seq(
    dependencies.betterFiles,
    dependencies.commonsCodec,
    dependencies.guara,
    dependencies.jjwtApi,
    dependencies.jjwtImpl,
    dependencies.jjwtJackson,
    dependencies.chimney,
    dependencies.firebase,
    dependencies.quillZio,
    dependencies.quillZioJdbc,
    dependencies.zioOptics,
    dependencies.postgresql,
    dependencies.zioTestSbt,
    dependencies.zioTestMagnolia,
  )

  lazy val serverDependencies = allDependencies ++ Seq(dependencies.commonsLang)

  def commonSettings(scalaVersion: String) = CrossVersion.partialVersion(scalaVersion) match {
    case Some((3, _))                  => Seq.empty
    case Some((2, 12)) | Some((2, 13)) => Seq("-Ywarn-unused:params")
    case _                             => Seq.empty
  }

  def stdSettings = Seq(
    ThisBuild / fork                         := true,
    ThisBuild / scalaVersion                 := ScalaVersion,
    ThisBuild / scalacOptions                := commonSettings(scalaVersion.value),
    ThisBuild / organization                 := "morbid",
    ThisBuild / version                      := "v0.0.3",
    ThisBuild / doc / sources                := Seq.empty,
    ThisBuild / packageDoc / publishArtifact := false,
    ThisBuild / resolvers                    += Resolver.mavenLocal,
    ThisBuild / testFrameworks               += new TestFramework("zio.test.sbt.ZTestFramework")
  )
}