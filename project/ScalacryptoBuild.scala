import sbt._
import sbt.Keys._

object ScalacryptoBuild extends Build {

  lazy val scalacrypto = Project(
    id = "scala-crypto",
    base = file("."),
    settings = Project.defaultSettings ++ Seq(
      name := "scala-crypto",
      organization := "com.yukinagae",
      version := "0.1-SNAPSHOT",
      scalaVersion := "2.10.2",
      // add other settings here
      libraryDependencies ++= Seq( //
        "org.specs2" %% "specs2" % "2.3.8" % "test", //
        "junit" % "junit" % "4.11" % "test",
        "org.bouncycastle" % "bcprov-jdk15on" % "1.50" //
        ) //
        ))
}
