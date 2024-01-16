package morbid

import zio.*

object pins {

  import morbid.config.MorbidConfig
  import morbid.types.Sha256Hash
  import morbid.types.{UserId, Pin}
  import morbid.repo.Repo
  import org.apache.commons.codec.digest.DigestUtils

  trait PinManager {
    def set(user: UserId, pin: Pin): Task[Unit]
    def validate(user: UserId, pin: Pin): Task[Boolean]
  }

  object PinManager {
    val layer = ZLayer.fromFunction(DatabasePinManager.apply _)
  }

  case class DatabasePinManager(config: MorbidConfig, repo: Repo) extends PinManager {

    private val prefix = config.pin.prefix

    override def set(user: UserId, pin: Pin): Task[Unit] = {
      val hash = DigestUtils.sha256Hex(prefix + Pin.value(pin))
      repo.setUserPin(user, Sha256Hash.of(hash))
    }

    override def validate(user: UserId, pin: Pin): Task[Boolean] = {
      val hash = DigestUtils.sha256Hex(prefix + Pin.value(pin))
      for {
        expected <- repo.getUserPin(user)
      } yield expected.map(Sha256Hash.value).map(Pin.of).contains(hash)
    }

  }
}