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
    def accountByProvider(code: ProviderCode)                   : Task[Option[RawAccount]]
    def accountByCode(code: AccountCode)                        : Task[Option[RawAccount]]
    def create(raw: RawUser)                                    : Task[RawUser]
    def userGiven(email: Email)                                 : Task[Option[RawUser]]
    def providerGiven(domain: Domain, code: Option[TenantCode]) : Task[Option[RawIdentityProvider]]
    def groupsGiven(account: AccountId, app: ApplicationCode)   : Task[Seq[RawGroup]]
    def setUserPin(user: UserId, pin: Sha256Hash)               : Task[Unit]
    def getUserPin(user: UserId)                                : Task[Option[Sha256Hash]]
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

    private inline given MappedEncoding[TenantId, Long]               (_.long)
    private inline given MappedEncoding[AccountId, Long]              (_.long)
    private inline given MappedEncoding[UserId, Long]                 (_.long)
    private inline given MappedEncoding[PinId, Long]                  (_.long)
    private inline given MappedEncoding[ApplicationId, Long]          (_.long)
    private inline given MappedEncoding[GroupId, Long]                (_.long)
    private inline given MappedEncoding[RoleId, Long]                 (_.long)
    private inline given MappedEncoding[PermissionId, Long]           (_.long)
    private inline given MappedEncoding[ProviderId, Long]             (_.long)
    private inline given MappedEncoding[TenantCode, String]           (_.string)
    private inline given MappedEncoding[TenantName, String]           (_.string)
    private inline given MappedEncoding[AccountName, String]          (_.string)
    private inline given MappedEncoding[AccountCode, String]          (_.string)
    private inline given MappedEncoding[ApplicationName, String]      (_.string)
    private inline given MappedEncoding[ApplicationCode, String]      (_.string)
    private inline given MappedEncoding[GroupName, String]            (_.string)
    private inline given MappedEncoding[GroupCode, String]            (_.string)
    private inline given MappedEncoding[RoleName, String]             (_.string)
    private inline given MappedEncoding[RoleCode, String]             (_.string)
    private inline given MappedEncoding[PermissionName, String]       (_.string)
    private inline given MappedEncoding[PermissionCode, String]       (_.string)
    private inline given MappedEncoding[ProviderName, String]         (_.string)
    private inline given MappedEncoding[ProviderCode, String]         (_.string)
    private inline given MappedEncoding[UserCode, String]             (_.string)
    private inline given MappedEncoding[Email, String]                (_.string)
    private inline given MappedEncoding[Domain, String]               (_.string)
    private inline given MappedEncoding[Sha256Hash, String]           (_.string)

    private inline given MappedEncoding[Long, TenantId]               (_.as[TenantId])
    private inline given MappedEncoding[Long, AccountId]              (_.as[AccountId])
    private inline given MappedEncoding[Long, UserId]                 (_.as[UserId])
    private inline given MappedEncoding[Long, PinId]                  (_.as[PinId])
    private inline given MappedEncoding[Long, ApplicationId]          (_.as[ApplicationId])
    private inline given MappedEncoding[Long, GroupId]                (_.as[GroupId])
    private inline given MappedEncoding[Long, RoleId]                 (_.as[RoleId])
    private inline given MappedEncoding[Long, PermissionId]           (_.as[PermissionId])
    private inline given MappedEncoding[Long, ProviderId]             (_.as[ProviderId])
    private inline given MappedEncoding[String, TenantCode]           (_.as[TenantCode])
    private inline given MappedEncoding[String, TenantName]           (_.as[TenantName])
    private inline given MappedEncoding[String, AccountName]          (_.as[AccountName])
    private inline given MappedEncoding[String, AccountCode]          (_.as[AccountCode])
    private inline given MappedEncoding[String, ApplicationName]      (_.as[ApplicationName])
    private inline given MappedEncoding[String, ApplicationCode]      (_.as[ApplicationCode])
    private inline given MappedEncoding[String, GroupName]            (_.as[GroupName])
    private inline given MappedEncoding[String, GroupCode]            (_.as[GroupCode])
    private inline given MappedEncoding[String, RoleName]             (_.as[RoleName])
    private inline given MappedEncoding[String, RoleCode]             (_.as[RoleCode])
    private inline given MappedEncoding[String, PermissionName]       (_.as[PermissionName])
    private inline given MappedEncoding[String, PermissionCode]       (_.as[PermissionCode])
    private inline given MappedEncoding[String, ProviderName]         (_.as[ProviderName])
    private inline given MappedEncoding[String, ProviderCode]         (_.as[ProviderCode])
    private inline given MappedEncoding[String, UserCode]             (_.as[UserCode])
    private inline given MappedEncoding[String, Email]                (_.as[Email])
    private inline given MappedEncoding[String, Domain]               (_.as[Domain])
    private inline given MappedEncoding[String, Sha256Hash]           (_.as[Sha256Hash])

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
    private inline def permissions  = quote { querySchema[PermissionRow]       ("permissions")        }
    private inline def user2role    = quote { querySchema[UserToRoleRow]       ("user_to_role")       }
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

    override def providerGiven(domain: Domain, tenant: Option[TenantCode]): Task[Option[RawIdentityProvider]] = {

      val code = tenant.getOrElse("DEFAULT".as[TenantCode])

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

    override def groupsGiven(acc: AccountId, code: ApplicationCode): Task[Seq[RawGroup]] = {
      inline def query = quote {
        for {
          app <- applications                        if app.active && app.deleted.isEmpty && app.code == lift(code)
          a2a <- account2app .join(_.app == app.id)  if               a2a.deleted.isEmpty && a2a.acc  == lift(acc)
          grp <- groups      .join(_.app == a2a.app) if               grp.deleted.isEmpty
        } yield grp
      }

      for {
        rows <- exec(run(query))
      } yield rows.map(_.transformInto[RawGroup])
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
  }
}