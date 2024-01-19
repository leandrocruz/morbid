package morbid

import zio.*

object roles {

  import morbid.types.*
  import morbid.domain.raw.*
  import morbid.repo.Repo

  trait RoleManager {
    def rolesFor (account: AccountId, app: ApplicationCode)                  : Task[Seq[RawRole]]
  }

  object RoleManager {
    val layer = ZLayer.fromFunction(LocalRoleManager.apply _)
  }

  case class LocalRoleManager(repo: Repo) extends RoleManager {
    override def rolesFor(account: AccountId, app: ApplicationCode)                 : Task[Seq[RawRole]] = repo.rolesGiven(account, app)
  }
}