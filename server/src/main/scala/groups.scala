package morbid

import zio.*

object groups {

  import morbid.types.*
  import morbid.domain.raw.*
  import morbid.repo.Repo

  trait GroupManager {
    def groupsFor (account: AccountId, app: ApplicationCode, filter: Seq[GroupCode] = Seq.empty) : Task[Seq[RawGroup]]
    def usersFor  (account: AccountId, app: ApplicationCode, group: GroupCode)                   : Task[Seq[RawUserEntry]]
  }

  object GroupManager {
    val layer = ZLayer.fromFunction(LocalGroupManager.apply _)
  }

  case class LocalGroupManager(repo: Repo) extends GroupManager {
    override def groupsFor(account: AccountId, app: ApplicationCode, filter: Seq[GroupCode]): Task[Seq[RawGroup]]     = repo.groupsGiven(account, app, filter)
    override def usersFor(account: AccountId, app: ApplicationCode, group: GroupCode)       : Task[Seq[RawUserEntry]] = repo.usersGiven(account, app, group)
  }
}