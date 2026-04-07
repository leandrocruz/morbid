package morbid.passwords

import morbid.config.MorbidConfig
import morbid.types.Password
import zio.*

import scala.util.Random

trait PasswordGenerator {
  def generate: Task[Password]
}

private case class DefaultPasswordGenerator(config: MorbidConfig) extends PasswordGenerator {
  override def generate: Task[Password] =
    ZIO.attempt {
      Password.of {
        Random.alphanumeric.take(12).mkString("")
      }
    }
}

object PasswordGenerator {
  val layer: ZLayer[MorbidConfig, Nothing, PasswordGenerator] = ZLayer.fromFunction(DefaultPasswordGenerator.apply)
}