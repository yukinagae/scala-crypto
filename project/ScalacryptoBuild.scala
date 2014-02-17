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
      scalaVersion := "2.10.2"
      // add other settings here
    )
  )
}
