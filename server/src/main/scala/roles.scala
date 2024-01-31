package morbid

import zio.*

object roles {

  import morbid.types.*
  import morbid.domain.raw.*
  import morbid.repo.Repo

  trait RoleManager {
    def rolesFor(account: AccountCode, app: ApplicationCode)                               : Task[Seq[RawRole]]
    def addRoles(account: AccountId, app: ApplicationId, user: UserId, roles: Seq[RoleId]) : Task[Unit]
  }

  object RoleManager {
    val layer = ZLayer.fromFunction(LocalRoleManager.apply _)
  }

  case class LocalRoleManager(repo: Repo) extends RoleManager {
    override def rolesFor(account: AccountCode, app: ApplicationCode)                               : Task[Seq[RawRole]] = repo.rolesGiven(account, app)
    override def addRoles(account: AccountId, app: ApplicationId, user: UserId, roles: Seq[RoleId]) : Task[Unit]         = repo.addRoles(account, app, user, roles)
  }
}