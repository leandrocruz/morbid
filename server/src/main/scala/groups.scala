package morbid

import zio.*

object groups {

  import morbid.types.*
  import morbid.domain.raw.*
  import morbid.repo.Repo

  object GroupManager {
    val layer = ZLayer.fromFunction(LocalGroupManager.apply _)
  }

  trait GroupManager {
    def groupsFor (account: AccountCode, app: ApplicationCode, filter: Seq[GroupCode] = Seq.empty) : Task[Seq[RawGroup]]
    def usersFor  (account: AccountCode, app: ApplicationCode, group: Option[GroupCode] = None)    : Task[Seq[RawUserEntry]]
    def addGroups (account: AccountId, app: ApplicationId, user: UserId, groups: Seq[GroupId])     : Task[Unit]

  }

  case class LocalGroupManager(repo: Repo) extends GroupManager {
    override def groupsFor (account: AccountCode, app: ApplicationCode, filter: Seq[GroupCode])         : Task[Seq[RawGroup]]     = repo.groupsGiven(account, app, filter)
    override def usersFor  (account: AccountCode, app: ApplicationCode, group: Option[GroupCode])       : Task[Seq[RawUserEntry]] = repo.usersGiven(account, app, group)
    override def addGroups (account: AccountId, app: ApplicationId, user: UserId, groups: Seq[GroupId]) : Task[Unit]              = repo.addGroups(account, app, user, groups)
  }
}