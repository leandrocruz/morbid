package morbid

import zio.*

object repo {

  import config.*
  import types.*
  import domain.*
  import domain.raw.*
  import proto.*
  import io.getquill.*
  import io.getquill.jdbczio.Quill
  import javax.sql.DataSource
  import java.sql.SQLException
  import java.time.LocalDateTime
  import io.scalaland.chimney.dsl._

  /**
   *
   * https://dbdiagram.io/d/Morbid-6577264356d8064ca0cd919d
   *
   * Table tenants {
   * id integer
   * }
   *
   * Table accounts {
   * id integer
   * tenant integer
   * }
   *
   * Table users {
   * id integer
   * account integer
   * }
   *
   * Table applications {
   * id integer
   * }
   *
   * Table groups {
   * id integer
   * // account integer
   * application integer
   *
   * }
   *
   * Table roles {
   * id integer
   * application integer
   * }
   *
   * Table permissions {
   * id integer
   * role integer
   * }
   *
   * Ref: accounts.tenant > tenants.id
   * Ref: users.account > accounts.id
   * // Ref: groups.account > accounts.id
   * Ref: groups.application > applications.id
   * Ref: roles.application > applications.id
   * Ref: permissions.role > roles.id
   *
   *
   * Table account_to_app {
   * account integer
   * app integer
   * }
   *
   * Ref: account_to_app.app     > applications.id
   * Ref: account_to_app.account > accounts.id
   *
   * Table user_to_group {
   * user interger
   * app integer
   * group integer
   *
   * }
   *
   * Table user_to_role {
   * user interger
   * app integer
   * role integer
   *
   * }
   *
   * Ref: user_to_group.user  > users.id
   * Ref: user_to_group.group > groups.id
   * Ref: user_to_group.app   > applications.id
   *
   * Ref: user_to_role.user  > users.id
   * Ref: user_to_role.role  > roles.id
   * Ref: user_to_role.app   > applications.id
   *
   */

  private case class TenantRow(
    id      : TenantId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
    active  : Boolean,
    code    : TenantCode,
    name    : TenantName,
  )

  private case class AccountRow(
    id       : AccountId,
    created  : LocalDateTime,
    deleted  : Option[LocalDateTime],
    tenant   : TenantId,
    active   : Boolean,
    code     : AccountCode,
    name     : AccountName,
  )

  private case class UserRow(
    id      : UserId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
    account : AccountId,
    kind    : Option[UserKind],
    code    : UserCode,
    active  : Boolean,
    email   : Email
  )

  private case class PinRow(
    id      : PinId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
    userId  : UserId,
    pin     : Sha256Hash,
  )
  
  private case class ApplicationRow(
    id      : ApplicationId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
    active  : Boolean,
    code    : ApplicationCode,
    name    : ApplicationName
  )

  private case class AccountToAppRow(
    acc     : AccountId,
    app     : ApplicationId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
  )

  private case class GroupRow(
    id      : GroupId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
    app     : ApplicationId,
    code    : GroupCode,
    name    : GroupName
  )

  private case class UserToGroupRow(
    usr     : UserId,
    app     : ApplicationId,
    grp     : GroupId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
  )

  private case class RoleRow(
    id      : RoleId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
    app     : ApplicationId,
    code    : RoleCode,
    name    : RoleName
  )

  private case class PermissionRow(
    id      : PermissionId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
    rid     : RoleId,
    code    : PermissionCode,
    name    : PermissionName
  )

  private case class UserToRoleRow(
    usr     : UserId,
    app     : ApplicationId,
    rid     : RoleId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime],
  )

  private case class IdentityProviderRow(
    id       : ProviderId,
    created  : LocalDateTime,
    deleted  : Option[LocalDateTime],
    account  : AccountId,
    active   : Boolean,
    domain   : Domain,
    kind     : ProviderKind, //SAML, UP, etc
    code     : ProviderCode,
    name     : ProviderName,
  )

  trait Repo {
    def accountByProvider(code: ProviderCode)                                                 : Task[Option[RawAccount]]
    def accountByCode(code: AccountCode)                                                      : Task[Option[RawAccount]]
    def addGroups(account: AccountId, app: ApplicationId, user: UserId, groups: Seq[GroupId]) : Task[Unit]
    def addRoles(account: AccountId, app: ApplicationId, user: UserId, roles: Seq[RoleId])    : Task[Unit]
    def applicationDetailsGiven(account: AccountCode)                                         : Task[Seq[RawApplicationDetails]]
    def applicationGiven(account: AccountCode, application: ApplicationCode)                  : Task[Option[RawApplication]]
    def create(raw: RawUser)                                                                  : Task[RawUser]
    def getUserPin(user: UserId)                                                              : Task[Option[Sha256Hash]]
    def groupsGiven(account: AccountCode, app: ApplicationCode, filter: Seq[GroupCode])       : Task[Seq[RawGroup]]
    def providerGiven(domain: Domain, code: Option[TenantCode])                               : Task[Option[RawIdentityProvider]]
    def providerGiven(account: AccountId)                                                     : Task[Option[RawIdentityProvider]]
    def rolesGiven(account: AccountCode, app: ApplicationCode)                                : Task[Seq[RawRole]]
    def setUserPin(user: UserId, pin: Sha256Hash)                                             : Task[Unit]
    def usersByAccount(app: ApplicationCode)                                                  : Task[Map[RawAccount, Int]]
    def userExists(code: UserCode)                                                            : Task[Boolean]
    def userGiven(email: Email)                                                               : Task[Option[RawUser]]
    def usersGiven(account: AccountCode, app: ApplicationCode, group: GroupCode)              : Task[Seq[RawUserEntry]]
  }

  object Repo {
    val layer: ZLayer[Any, Throwable, Repo] = Quill.DataSource.fromPrefix("database") >>> ZLayer.fromFunction(DatabaseRepo.apply _)
  }

  private case class DatabaseRepo(ds: DataSource) extends Repo {

    private type ApplicationGroups        = (ApplicationId, GroupRow)
    private type ApplicationRolesAndPerms = (ApplicationId, RoleRow, PermissionRow)
    private type AppMap[T]                = Map[ApplicationId, Seq[T]]

    import ctx._
    import extras._

    private lazy val ctx = new PostgresZioJdbcContext(SnakeCase)

    private inline given InsertMeta[TenantRow]           = insertMeta[TenantRow]           (_.id)
    private inline given InsertMeta[AccountRow]          = insertMeta[AccountRow]          (_.id)
    private inline given InsertMeta[UserRow]             = insertMeta[UserRow]             (_.id)
    private inline given InsertMeta[PinRow]              = insertMeta[PinRow]              (_.id)
    private inline given InsertMeta[ApplicationRow]      = insertMeta[ApplicationRow]      (_.id)
    private inline given InsertMeta[GroupRow]            = insertMeta[GroupRow]            (_.id)
    private inline given InsertMeta[RoleRow]             = insertMeta[RoleRow]             (_.id)
    private inline given InsertMeta[PermissionRow]       = insertMeta[PermissionRow]       (_.id)
    private inline given InsertMeta[IdentityProviderRow] = insertMeta[IdentityProviderRow] (_.id)

    private inline given MappedEncoding[TenantId, Long]               (TenantId.value)
    private inline given MappedEncoding[AccountId, Long]              (AccountId.value)
    private inline given MappedEncoding[UserId, Long]                 (UserId.value)
    private inline given MappedEncoding[PinId, Long]                  (PinId.value)
    private inline given MappedEncoding[ApplicationId, Long]          (ApplicationId.value)
    private inline given MappedEncoding[GroupId, Long]                (GroupId.value)
    private inline given MappedEncoding[RoleId, Long]                 (RoleId.value)
    private inline given MappedEncoding[PermissionId, Long]           (PermissionId.value)
    private inline given MappedEncoding[ProviderId, Long]             (ProviderId.value)
    private inline given MappedEncoding[TenantCode, String]           (TenantCode.value)
    private inline given MappedEncoding[TenantName, String]           (TenantName.value)
    private inline given MappedEncoding[AccountName, String]          (AccountName.value)
    private inline given MappedEncoding[AccountCode, String]          (AccountCode.value)
    private inline given MappedEncoding[ApplicationName, String]      (ApplicationName.value)
    private inline given MappedEncoding[ApplicationCode, String]      (ApplicationCode.value)
    private inline given MappedEncoding[GroupName, String]            (GroupName.value)
    private inline given MappedEncoding[GroupCode, String]            (GroupCode.value)
    private inline given MappedEncoding[RoleName, String]             (RoleName.value)
    private inline given MappedEncoding[RoleCode, String]             (RoleCode.value)
    private inline given MappedEncoding[PermissionName, String]       (PermissionName.value)
    private inline given MappedEncoding[PermissionCode, String]       (PermissionCode.value)
    private inline given MappedEncoding[ProviderName, String]         (ProviderName.value)
    private inline given MappedEncoding[ProviderCode, String]         (ProviderCode.value)
    private inline given MappedEncoding[UserCode, String]             (UserCode.value)
    private inline given MappedEncoding[Email, String]                (Email.value)
    private inline given MappedEncoding[Domain, String]               (Domain.value)
    private inline given MappedEncoding[Sha256Hash, String]           (Sha256Hash.value)

    private inline given MappedEncoding[Long, TenantId]               (TenantId.of)
    private inline given MappedEncoding[Long, AccountId]              (AccountId.of)
    private inline given MappedEncoding[Long, UserId]                 (UserId.of)
    private inline given MappedEncoding[Long, PinId]                  (PinId.of)
    private inline given MappedEncoding[Long, ApplicationId]          (ApplicationId.of)
    private inline given MappedEncoding[Long, GroupId]                (GroupId.of)
    private inline given MappedEncoding[Long, RoleId]                 (RoleId.of)
    private inline given MappedEncoding[Long, PermissionId]           (PermissionId.of)
    private inline given MappedEncoding[Long, ProviderId]             (ProviderId.of)
    private inline given MappedEncoding[String, TenantCode]           (TenantCode.of)
    private inline given MappedEncoding[String, TenantName]           (TenantName.of)
    private inline given MappedEncoding[String, AccountName]          (AccountName.of)
    private inline given MappedEncoding[String, AccountCode]          (AccountCode.of)
    private inline given MappedEncoding[String, ApplicationName]      (ApplicationName.of)
    private inline given MappedEncoding[String, ApplicationCode]      (ApplicationCode.of)
    private inline given MappedEncoding[String, GroupName]            (GroupName.of)
    private inline given MappedEncoding[String, GroupCode]            (GroupCode.of)
    private inline given MappedEncoding[String, RoleName]             (RoleName.of)
    private inline given MappedEncoding[String, RoleCode]             (RoleCode.of)
    private inline given MappedEncoding[String, PermissionName]       (PermissionName.of)
    private inline given MappedEncoding[String, PermissionCode]       (PermissionCode.of)
    private inline given MappedEncoding[String, ProviderName]         (ProviderName.of)
    private inline given MappedEncoding[String, ProviderCode]         (ProviderCode.of)
    private inline given MappedEncoding[String, UserCode]             (UserCode.of)
    private inline given MappedEncoding[String, Email]                (Email.of)
    private inline given MappedEncoding[String, Domain]               (Domain.of)
    private inline given MappedEncoding[String, Sha256Hash]           (Sha256Hash.of)

    private inline given MappedEncoding[String, UserKind]             (UserKind.valueOf)
    private inline given MappedEncoding[UserKind, String]             (_.toString)
    private inline given MappedEncoding[String, ProviderKind]         (ProviderKind.valueOf)
    private inline given MappedEncoding[ProviderKind, String]         (_.toString)

    private inline def tenants      = quote { querySchema[TenantRow]           ("tenants")            }
    private inline def accounts     = quote { querySchema[AccountRow]          ("accounts")           }
    private inline def users        = quote { querySchema[UserRow]             ("users")              }
    private inline def pins         = quote { querySchema[PinRow]              ("pins")               }
    private inline def applications = quote { querySchema[ApplicationRow]      ("applications")       }
    private inline def account2app  = quote { querySchema[AccountToAppRow]     ("account_to_app")     }
    private inline def groups       = quote { querySchema[GroupRow]            ("groups")             }
    private inline def user2group   = quote { querySchema[UserToGroupRow]      ("user_to_group")      }
    private inline def roles        = quote { querySchema[RoleRow]             ("roles")              }
    private inline def user2role    = quote { querySchema[UserToRoleRow]       ("user_to_role")       }
    private inline def permissions  = quote { querySchema[PermissionRow]       ("permissions")        }
    private inline def providers    = quote { querySchema[IdentityProviderRow] ("identity_providers") }

    private def exec[T](zio: ZIO[DataSource, SQLException, T]): Task[T] = zio.provide(ZLayer.succeed(ds))

    override def userGiven(email: Email): Task[Option[RawUser]] = {

      inline def appQuery = quote {
        for {
          usr <- users                                   if usr.active && usr.deleted.isEmpty && usr.email == lift(email)
          acc <- accounts     .join(_.id == usr.account) if acc.active && acc.deleted.isEmpty
          ten <- tenants      .join(_.id == acc.tenant)  if ten.active && ten.deleted.isEmpty
          a2a <- account2app  .join(_.acc == acc.id)     if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)     if app.active && app.deleted.isEmpty
        } yield (ten, acc, usr, app)
      }

      def asRawUser(rows: Seq[(TenantRow, AccountRow, UserRow, ApplicationRow)]): Task[Option[RawUser]] = {

        def build(tenant: TenantRow, account: AccountRow, user: UserRow): Task[Option[RawUser]] = {
          for {
            details <- ZIO.attempt {
                         user
                           .into[RawUserDetails]
                           .withFieldConst(_.tenant, account.tenant)
                           .withFieldConst(_.tenantCode, tenant.code)
                           .withFieldConst(_.accountCode, account.code)
                           .transform
                       }
            apps    <- ZIO.attempt { rows.map(_._4).map(_.transformInto[RawApplicationDetails]).map(RawApplication(_)) }
          } yield Some {
            RawUser(details = details, applications = apps)
          }
        }

        rows.headOption match {
          case None                     => ZIO.succeed(None)
          case Some((tenant, account, user, _)) => build(tenant, account, user)
        }
      }

      def groupsAndRoles(usr: RawUser): Task[Option[RawUser]] = {

        val apps = usr.applications.map(_.details.id)
        val uid  = usr.details.id

        inline def groupQuery = quote {
          for {
            u2g <- user2group                   if u2g.deleted.isEmpty && u2g.usr == lift(uid) && liftQuery(apps).contains(u2g.app)
            grp <- groups.join(_.id == u2g.grp) if grp.deleted.isEmpty
          } yield (u2g.app, grp)
        }

        inline def roleQuery = quote {
          for {
            u2r  <- user2role                          if u2r.deleted.isEmpty && u2r.usr == lift(uid) && liftQuery(apps).contains(u2r.app)
            role <- roles.join(_.id == u2r.rid)        if role.deleted.isEmpty
            perm <- permissions.join(_.rid == role.id) if perm.deleted.isEmpty
          } yield (u2r.app, role, perm)
        }

        def splitGroups(groups: Seq[ApplicationGroups]): Task[AppMap[RawGroup]] = {
          ZIO.attempt {
            groups.groupBy(_._1).view.mapValues(_.map(_._2).map(_.transformInto[RawGroup])).toMap
          }
        }

        def splitRoles(roles: Seq[ApplicationRolesAndPerms]): Task[AppMap[RawRole]] = {

          def asRoles(seq: Seq[(RoleRow, PermissionRow)]): Seq[RawRole] = {
            seq.groupBy(_._1).view.mapValues(_.map(_._2)).toMap.map {
              case (role, perms) =>
                val raw = role.into[RawRole].enableDefaultValues.transform
                raw.copy(permissions = perms.map(_.transformInto[RawPermission]))
            }.toSeq
          }

          ZIO.attempt {
            roles.map {
              case (app, role, perm) => (app, (role, perm))
            }.groupBy(_._1).view.mapValues(_.map(_._2)).mapValues(asRoles).toMap
          }
        }

        def updateApps(groupsByApp: AppMap[RawGroup], rolesByApp: AppMap[RawRole]) = {
          usr.applications.map { app =>
            app.copy(
              groups = groupsByApp.getOrElse(app.details.id, Seq.empty),
              roles  = rolesByApp .getOrElse(app.details.id, Seq.empty)
            )
          }
        }

        for {
          myGroups    <- exec(run(groupQuery))
          myRoles     <- exec(run(roleQuery))
          groupsByApp <- splitGroups(myGroups)
          rolesByApp  <- splitRoles(myRoles)
        } yield Some(usr.copy(applications = updateApps(groupsByApp, rolesByApp)))
      }

      for {
        rows   <- exec(run(appQuery))
        maybe  <- asRawUser(rows)
        result <- maybe match
          case None      => ZIO.succeed(None)
          case Some(usr) => groupsAndRoles(usr)
      } yield result
    }

    override def userExists(code: UserCode): Task[Boolean] = {
      inline def query = quote {
        for {
          ten <- tenants                             if ten.active && ten.deleted.isEmpty
          acc <- accounts .join(_.tenant == ten.id)  if acc.active && acc.deleted.isEmpty
          usr <- users    .join(_.account == acc.id) if usr.active && usr.deleted.isEmpty && usr.code == lift(code)
        } yield usr
      }

      for {
        rows <- exec(run(query))
      } yield rows.length == 1
    }

    override def create(raw: RawUser): Task[RawUser] = {

      val row = raw.details.transformInto[UserRow]

      val stmt = quote {
        users.insertValue(lift(row)).returning(_.id)
      }

      val optic = userDetailsLens >>> idLens

      for {
        id     <- exec(run(stmt))
        result <- ZIO.fromEither(optic.set(id)(raw))
      } yield result
    }

    override def accountByProvider(code: ProviderCode): Task[Option[RawAccount]] = {

      inline def query = quote {
        for {
          t <- tenants                           if t.active && t.deleted.isEmpty
          a <- accounts.join(_.tenant == t.id)   if a.active && a.deleted.isEmpty
          p <- providers.join(_.account == a.id) if p.active && p.deleted.isEmpty && p.code == lift(code)
        } yield (t, a)
      }

      for {
        rows   <- exec(run(query))
      } yield rows.headOption.map {
        case (tenant, account) => account.into[RawAccount].withFieldConst(_.tenantCode, tenant.code).transform
      }
    }

    override def providerGiven(account: AccountId): Task[Option[RawIdentityProvider]] = {
      inline def query = quote {
        for {
          t <- tenants                                                        if t.active && t.deleted.isEmpty
          a <- accounts  .join(_.tenant == t.id)                              if a.active && a.deleted.isEmpty && a.id == lift(account)
          p <- providers .join(_.account == a.id).sortBy(_.created)(Ord.desc) if p.active && p.deleted.isEmpty
        } yield p
      }

      for {
        rows <- exec(run(query))
      } yield rows.headOption.map(_.transformInto[RawIdentityProvider])
    }

    override def providerGiven(domain: Domain, tenant: Option[TenantCode]): Task[Option[RawIdentityProvider]] = {

      val code = tenant.getOrElse(TenantCode.of("DEFAULT"))

      inline def query = quote {
        for {
          t <- tenants                                                       if t.active && t.deleted.isEmpty && t.code == lift(code)
          a <- accounts .join(_.tenant == t.id)                              if a.active && a.deleted.isEmpty
          p <- providers.join(_.account == a.id).sortBy(_.created)(Ord.desc) if p.active && p.deleted.isEmpty && p.domain == lift(domain)
        } yield p
      }

      for {
        rows <- exec(run(query))
      } yield rows.headOption.map(_.transformInto[RawIdentityProvider])

    }

    override def groupsGiven(account: AccountCode, application: ApplicationCode, filter: Seq[GroupCode] = Seq.empty): Task[Seq[RawGroup]] = {
      inline def query = quote {
        for {
          ten <- tenants                                if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join(_.tenant == ten.id) if acc.deleted.isEmpty && acc.active && acc.code == lift(account)
          a2a <- account2app  .join(_.acc == acc.id)    if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)    if app.deleted.isEmpty && app.active && app.code == lift(application)
          grp <- groups       .join(_.app == a2a.app)   if grp.deleted.isEmpty && (lift(filter.isEmpty) || liftQuery(filter).contains(grp.code))
        } yield grp
      }

      for {
        rows <- exec(run(query))
      } yield rows.map(_.transformInto[RawGroup])
    }

    override def rolesGiven(account: AccountCode, application: ApplicationCode): Task[Seq[RawRole]] = {

      def toRole(role: RoleRow, data: Seq[(RoleRow, PermissionRow)]): RawRole = {
        val perms = data.map(_._2).distinct.map(_.transformInto[RawPermission])
        role.into[RawRole].withFieldConst(_.permissions, perms).transform
      }

      inline def query: Quoted[Query[(RoleRow, PermissionRow)]] = quote {
        for {
          ten <- tenants                                if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join(_.tenant == ten.id) if acc.deleted.isEmpty && acc.active && acc.code == lift(account)
          a2a <- account2app  .join(_.acc == acc.id)    if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)    if app.deleted.isEmpty && app.active && app.code == lift(application)
          rol <- roles        .join(_.app == app.id)    if rol.deleted.isEmpty
          per <- permissions  .join(_.rid == rol.id)    if per.deleted.isEmpty
        } yield (rol, per)
      }

      for {
        rows <- exec(run(query))
      } yield rows.groupBy(_._1).map(toRole).toSeq
    }

    private inline def printQuery[T](inline quoted: Quoted[Query[T]]): Task[Unit] = {
      for {
        str <- exec(ctx.translate(quoted, prettyPrint = false))
        _   <- ZIO.log(str)
      } yield ()
    }

    override def usersGiven(account: AccountCode, application: ApplicationCode, group: GroupCode): Task[Seq[RawUserEntry]] = {
      inline def query = quote {
        for {
          ten <- tenants                                 if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join(_.tenant == ten.id)  if acc.deleted.isEmpty && acc.active && acc.code == lift(account)
          a2a <- account2app  .join(_.acc == acc.id)     if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)     if app.deleted.isEmpty && app.active && app.code == lift(application)
          grp <- groups       .join(_.app == app.id)     if grp.deleted.isEmpty && grp.code == lift(group)
          u2g <- user2group   .join(_.app == app.id)     if u2g.deleted.isEmpty && u2g.grp  == grp.id
          usr <- users        .join(_.id  == u2g.usr)    if usr.deleted.isEmpty && usr.active
        } yield usr
      }

      for {
        //_    <- printQuery(query)
        rows <- exec(run(query))
      } yield rows.map(_.transformInto[RawUserEntry])
    }

    override def accountByCode(code: AccountCode): Task[Option[RawAccount]] = {
      inline def query = quote {
        for {
          t <- tenants                          if t.active && t.deleted.isEmpty
          a <- accounts .join(_.tenant == t.id) if a.active && a.deleted.isEmpty && a.code == lift(code)
        } yield (t, a)
      }

      for {
        rows <- exec(run(query))
      } yield rows.headOption.map {
        case (tenant, account) => account.into[RawAccount].withFieldConst(_.tenant, tenant.id).withFieldConst(_.tenantCode, tenant.code).transform
      }
    }

    override def applicationDetailsGiven(account: AccountCode): Task[Seq[RawApplicationDetails]] = {

      inline def query = quote {
        for {
          ten <- tenants                                if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join(_.tenant == ten.id) if acc.deleted.isEmpty && acc.active && acc.code == lift(account)
          a2a <- account2app  .join(_.acc == acc.id)    if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)    if app.deleted.isEmpty && app.active
        } yield app
      }

      for {
        rows <- exec(run(query))
      } yield rows.map(_.transformInto[RawApplicationDetails])
    }

    override def applicationGiven(account: AccountCode, application: ApplicationCode): Task[Option[RawApplication]] = {

      def appFrom(row: ApplicationRow): Task[Option[RawApplication]] = {
        for {
          f1     <- groupsGiven(account, application).fork
          f2     <- rolesGiven (account, application).fork
          groups <- f1.join
          roles  <- f2.join

        } yield Some(RawApplication(
          details = row.transformInto[RawApplicationDetails],
          groups  = groups,
          roles   = roles
        ))

      }

      inline def query = quote {
        for {
          ten <- tenants                                 if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join(_.tenant == ten.id)  if acc.deleted.isEmpty && acc.active && acc.code == lift(account)
          a2a <- account2app  .join(_.acc == acc.id)     if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)     if app.deleted.isEmpty && app.active && app.code == lift(application)
        } yield app
      }

      for {
        rows   <- exec(run(query))
        result <- rows.headOption match {
          case None      => ZIO.none
          case Some(app) => appFrom(app)
        }
      } yield result
    }

    override def addGroups(account: AccountId, app: ApplicationId, user: UserId, groups: Seq[GroupId]): Task[Unit] = {
      def insertValues(rows: Seq[UserToGroupRow]) = quote {
        liftQuery(rows).foreach(row => user2group.insertValue(row))
      }

      for {
        now  <- Clock.localDateTime
        rows =  groups.map(grp => UserToGroupRow(usr = user, app = app, grp = grp, created = now, deleted = None))
        _    <- exec(run(insertValues(rows)))
      } yield ()
    }

    override def addRoles(account: AccountId, app: ApplicationId, user: UserId, roles: Seq[RoleId]): Task[Unit] = {
      def insertValues(rows: Seq[UserToRoleRow]) = quote {
        liftQuery(rows).foreach(row => user2role.insertValue(row))
      }

      for {
        now <- Clock.localDateTime
        rows = roles.map(rid => UserToRoleRow(usr = user, app = app, rid = rid, created = now, deleted = None))
        _ <- exec(run(insertValues(rows)))
      } yield ()
    }

    override def setUserPin(user: UserId, pin: Sha256Hash): Task[Unit] = {

      def row(now: LocalDateTime) = PinRow(
        id      = PinId.of(0),
        created = now,
        deleted = None,
        userId  = user ,
        pin     = pin
      )

      inline def stmt(row: PinRow) = quote {
        pins.insertValue(lift(row)).returning(_.id)
      }

      for {
        now <- Clock.localDateTime
        _   <- exec(run(stmt(row(now))))
      } yield ()
    }

    override def getUserPin(user: UserId): Task[Option[Sha256Hash]] = {
      inline def query = quote {
        (for {
          p <- pins if p.deleted.isEmpty && p.userId == lift(user)
        } yield p).sortBy(_.created)(Ord.desc)
      }

      for {
        rows <- exec(run(query))
      } yield rows.headOption.map { _.pin }
    }

    override def usersByAccount(code: ApplicationCode): Task[Map[RawAccount, Int]] = {
      inline def query = quote {
        (for {
          app <- applications                           if app.active && app.deleted.isEmpty && app.code == lift(code)
          a2a <- account2app .join(_.app == app.id)     if               a2a.deleted.isEmpty
          acc <- accounts    .join(_.id == a2a.acc)     if acc.active && acc.deleted.isEmpty
          usr <- users       .join(_.account == acc.id) if usr.active && usr.deleted.isEmpty
        } yield (acc, usr)).groupBy(_._1).map {
          case (acc, users) => (acc, users.size)
        }
      }

      for {
        _    <- printQuery(query)
        rows <- exec(run(query))
      } yield rows.map {
        case (account, count) => account.into[RawAccount].withFieldConst(_.tenantCode, TenantCode.of("")).transform -> count.toInt
      }.toMap
    }
  }
}