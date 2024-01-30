package morbid

import zio.*

object groups {

  import morbid.types.*
  import morbid.domain.raw.*
  import morbid.repo.Repo

  trait GroupManager {
    def groupsFor (account: AccountCode, app: ApplicationCode, filter: Seq[GroupCode] = Seq.empty)   : Task[Seq[RawGroup]]
    def usersFor  (account: AccountCode, app: ApplicationCode, group: GroupCode)                     : Task[Seq[RawUserEntry]]
    //def setGroups (account: AccountId, app: ApplicationCode, user: UserId, groups: Seq[GroupCode]) : Task[Unit]

  }

  object GroupManager {
    val layer = ZLayer.fromFunction(LocalGroupManager.apply _)
  }

  case class LocalGroupManager(repo: Repo) extends GroupManager {
    override def groupsFor(account: AccountCode, app: ApplicationCode, filter: Seq[GroupCode]) : Task[Seq[RawGroup]]     = repo.groupsGiven(account, app, filter)
    override def usersFor(account: AccountCode, app: ApplicationCode, group: GroupCode)        : Task[Seq[RawUserEntry]] = repo.usersGiven(account, app, group)

//    def setGroups(account: AccountId, app: ApplicationCode, user: UserId, groups: Seq[GroupCode]): Task[Unit] =
//
//      for {
//        appGroups <- repo.groupsGiven(account, app)
//        _         <- groups.forall(code => appGroups.exists(_.code == code))
//      } yield ???
//
//      ???
  }
}