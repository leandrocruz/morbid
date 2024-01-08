package morbid

import zio.*

object pins {

  import morbid.types.{UserId, Pin}
  import morbid.repo.Repo

  trait PinManager {
    def set(user: UserId, pin: Pin): Task[Unit]
  }

  object PinManager {
    val layer = ZLayer.fromFunction(DatabasePinManager.apply _)
  }

  case class DatabasePinManager(repo: Repo) extends PinManager {
    override def set(user: UserId, pin: Pin): Task[Unit] = repo.setUserPin(user, pin)
  }
}