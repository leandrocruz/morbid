import sbt._
import sbt.Keys._

object BuildHelper {

  val ScalaVersion = "3.3.0"

  lazy val dependencies = new {
    val guara           = "guara"                %% "guara-framework"   % "v0.0.2-SNAPSHOT" changing()
    val betterFiles     = "com.github.pathikrit" %% "better-files"      % "3.9.2"
    val jjwtApi         = "io.jsonwebtoken"      % "jjwt-api"           % "0.12.3"
    val jjwtImpl        = "io.jsonwebtoken"      % "jjwt-impl"          % "0.12.3"
    val jjwtJackson     = "io.jsonwebtoken"      % "jjwt-jackson"       % "0.12.3"
    val chimney         = "io.scalaland"         %% "chimney"           % "0.8.2"
    val firebase        = "com.google.firebase"  %  "firebase-admin"    % "9.1.1"
    val quillZio        = "io.getquill"          %% "quill-zio"         % "4.8.0"
    val quillZioJdbc    = "io.getquill"          %% "quill-jdbc-zio"    % "4.8.0"
    val zioOptics       = "dev.zio"              %% "zio-optics"        % "0.2.1"
    val postgresql      = "org.postgresql"       %  "postgresql"        % "42.5.4"
    val zioTest         = "dev.zio"              %% "zio-test"          % "2.0.19" % Test
    val zioTestSbt      = "dev.zio"              %% "zio-test-sbt"      % "2.0.19" % Test
    val zioTestMagnolia = "dev.zio"              %% "zio-test-magnolia" % "2.0.19" % Test
  }

  lazy val allDependencies = Seq(
    dependencies.guara,
    dependencies.betterFiles,
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
    ThisBuild / name                         := "morbid",
    ThisBuild / version                      := "v0.0.1-SNAPSHOT",
    ThisBuild / doc / sources                := Seq.empty,
    ThisBuild / packageDoc / publishArtifact := false,
    ThisBuild / resolvers                    += Resolver.mavenLocal,
    ThisBuild / testFrameworks               += new TestFramework("zio.test.sbt.ZTestFramework")
  )
}