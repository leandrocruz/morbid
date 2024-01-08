package morbid

import zio.*

object groups {

  import morbid.types.*
  import morbid.domain.raw.RawGroup
  import morbid.repo.Repo

  trait GroupManager {
    def groupsFor(account: AccountId, app: ApplicationCode): Task[Seq[RawGroup]]
  }

  object GroupManager {
    val layer = ZLayer.fromFunction(LocalGroupManager.apply _)
  }

  case class LocalGroupManager(repo: Repo) extends GroupManager {
    override def groupsFor(account: AccountId, app: ApplicationCode): Task[Seq[RawGroup]] = repo.groupsGiven(account, app)
  }
}