package morbid

import zio.*

object repo {

  import types.*
  import domain.*
  import domain.raw.*
  import commands.*
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
    acc     : AccountId,
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
    def exec[R](command: Command[R]): Task[R]
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

    override def exec[R](command: Command[R]): Task[R] = {
      command match
        case r: CreateGroup           => create(r)
        case r: CreateUser            => create(r)
        case r: DefineUserPin         => setUserPin(r)
        case r: GetUserPin            => getUserPin(r)
        case r: FindAccountByCode     => accountByCode(r)
        case r: FindAccountByProvider => accountByProvider(r)
        case r: FindApplication       => applicationGiven(r)
        case r: FindApplications      => applicationDetailsGiven(r)
        case r: FindGroups            => groupsGiven(r)
        case r: FindProviderByAccount => providerGiven(r)
        case r: FindProviderByDomain  => providerGiven(r)
        case r: FindRoles             => rolesGiven(r)
        case r: FindUsersByCodes      => usersGiven(r)
        case r: FindUserByEmail       => userGiven(r)
        case r: FindUsersInGroup      => usersGiven(r)
        case r: LinkUsersToGroups     => addGroups(r)
        case r: LinkUsersToRoles      => addRoles(r)
        case r: ReportUsersByAccount  => usersByAccount(r)
        case r: UserExists            => userExists(r)
    }

    private def userGiven(request: FindUserByEmail): Task[Option[RawUser]] = {

      inline def appQuery = quote {
        for {
          usr <- users                                   if usr.active && usr.deleted.isEmpty && usr.email == lift(request.email)
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

    private def userExists(request: UserExists): Task[Boolean] = {
      inline def query = quote {
        for {
          ten <- tenants                             if ten.active && ten.deleted.isEmpty
          acc <- accounts .join(_.tenant == ten.id)  if acc.active && acc.deleted.isEmpty
          usr <- users    .join(_.account == acc.id) if usr.active && usr.deleted.isEmpty && usr.code == lift(request.code)
        } yield usr
      }

      for {
        rows <- exec(run(query))
      } yield rows.length == 1
    }

    private def create(req: CreateUser): Task[RawUser] = {

      def build(created: LocalDateTime) = {
        RawUser(details = RawUserDetails(
          id          = UserId.of(0),
          tenant      = req.account.tenant,
          tenantCode  = req.account.tenantCode,
          account     = req.account.id,
          accountCode = req.account.code,
          created     = created,
          active      = true,
          code        = req.code,
          email       = req.email,
          kind        = req.kind
        ))
      }

      def store(raw: RawUser) = {
        val row = raw.details.transformInto[UserRow]

        inline def stmt = quote {
          users.insertValue(lift(row)).returning(_.id)
        }

        val optic = userDetailsLens >>> idLens

        for {
          id     <- exec(run(stmt))
          result <- ZIO.fromEither(optic.set(id)(raw))
        } yield result
      }

      for {
        now <- Clock.localDateTime
        raw =  build(now)
        usr <- store(raw)
      } yield usr

    }

    private def create(request: CreateGroup): Task[RawGroup] = {

      def store = {
        val row = request
          .group
          .into[GroupRow]
          .withFieldConst(_.app, request.application.details.id)
          .withFieldConst(_.acc, request.account)
          .transform

        inline def stmt = quote {
          groups.insertValue(lift(row)).returning(_.id)
        }

        for
          id <- exec(run(stmt))
        yield request.group.copy(id = id)
      }

      for
        group <- store
        users <- usersGiven (FindUsersByCodes(request.account, request.users))
        _     <- addGroups  (LinkUsersToGroups(request.application.details.id, users.map(_.id), Seq(group.id)))
      yield group

    }

    private def accountByProvider(request: FindAccountByProvider): Task[Option[RawAccount]] = {

      inline def query = quote {
        for {
          t <- tenants                           if t.active && t.deleted.isEmpty
          a <- accounts.join(_.tenant == t.id)   if a.active && a.deleted.isEmpty
          p <- providers.join(_.account == a.id) if p.active && p.deleted.isEmpty && p.code == lift(request.code)
        } yield (t, a)
      }

      for {
        rows   <- exec(run(query))
      } yield rows.headOption.map {
        case (tenant, account) => account.into[RawAccount].withFieldConst(_.tenantCode, tenant.code).transform
      }
    }

    private def providerGiven(request: FindProviderByAccount): Task[Option[RawIdentityProvider]] = {
      inline def query = quote {
        for {
          t <- tenants                                                        if t.active && t.deleted.isEmpty
          a <- accounts  .join(_.tenant == t.id)                              if a.active && a.deleted.isEmpty && a.id == lift(request.account)
          p <- providers .join(_.account == a.id).sortBy(_.created)(Ord.desc) if p.active && p.deleted.isEmpty
        } yield p
      }

      for {
        rows <- exec(run(query))
      } yield rows.headOption.map(_.transformInto[RawIdentityProvider])
    }

    private def providerGiven(request: FindProviderByDomain): Task[Option[RawIdentityProvider]] = {

      val code = request.code.getOrElse(TenantCode.of("DEFAULT"))

      inline def query = quote {
        for {
          t <- tenants                                                       if t.active && t.deleted.isEmpty && t.code == lift(code)
          a <- accounts .join(_.tenant == t.id)                              if a.active && a.deleted.isEmpty
          p <- providers.join(_.account == a.id).sortBy(_.created)(Ord.desc) if p.active && p.deleted.isEmpty && p.domain == lift(request.domain)
        } yield p
      }

      for {
        rows <- exec(run(query))
      } yield rows.headOption.map(_.transformInto[RawIdentityProvider])

    }

    private def groupsGiven(request: FindGroups): Task[Seq[RawGroup]] = {
      inline def query = quote {
        for {
          ten <- tenants                                if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join(_.tenant == ten.id) if acc.deleted.isEmpty && acc.active && acc.code == lift(request.account)
          a2a <- account2app  .join(_.acc == acc.id)    if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)    if app.deleted.isEmpty && app.active && app.code == lift(request.app)
          grp <- groups       .join(_.app == a2a.app)   if grp.deleted.isEmpty && grp.acc == acc.id && (lift(request.filter.isEmpty) || liftQuery(request.filter).contains(grp.code))
        } yield grp
      }

      for {
        rows <- exec(run(query))
      } yield rows.map(_.transformInto[RawGroup])
    }

    private def rolesGiven(request: FindRoles): Task[Seq[RawRole]] = {

      def toRole(role: RoleRow, data: Seq[(RoleRow, PermissionRow)]): RawRole = {
        val perms = data.map(_._2).distinct.map(_.transformInto[RawPermission])
        role.into[RawRole].withFieldConst(_.permissions, perms).transform
      }

      inline def query: Quoted[Query[(RoleRow, PermissionRow)]] = quote {
        for {
          ten <- tenants                                if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join(_.tenant == ten.id) if acc.deleted.isEmpty && acc.active && acc.code == lift(request.account)
          a2a <- account2app  .join(_.acc == acc.id)    if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)    if app.deleted.isEmpty && app.active && app.code == lift(request.app)
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

    private def usersGiven(request: FindUsersInGroup): Task[Seq[RawUserEntry]] = {

      inline def groupUsers(code: GroupCode) = {
        quote {
          for {
            ten <- tenants                                 if ten.deleted.isEmpty && ten.active
            acc <- accounts     .join(_.tenant == ten.id)  if acc.deleted.isEmpty && acc.active && acc.code == lift(request.account)
            a2a <- account2app  .join(_.acc    == acc.id)  if a2a.deleted.isEmpty
            app <- applications .join(_.id     == a2a.app) if app.deleted.isEmpty && app.active && app.code == lift(request.app)
            grp <- groups       .join(_.app    == app.id)  if grp.deleted.isEmpty && grp.acc == acc.id && grp.code == lift(code)
            u2g <- user2group   .join(_.app    == app.id)  if u2g.deleted.isEmpty && u2g.grp  == grp.id
            usr <- users        .join(_.id     == u2g.usr) if usr.deleted.isEmpty && usr.active
          } yield usr
        }
      }

      inline def appUsers = {
        quote {
          for {
            ten <- tenants                                 if ten.deleted.isEmpty && ten.active
            acc <- accounts     .join(_.tenant == ten.id)  if acc.deleted.isEmpty && acc.active && acc.code == lift(request.account)
            usr <- users        .join(_.account == acc.id) if usr.deleted.isEmpty && usr.active
          } yield usr
        }
      }

      inline def query = request.group match
        case Some(code) => groupUsers(code)
        case None       => appUsers

      for {
        _    <- printQuery(query)
        rows <- exec(run(query))
      } yield rows.map(_.transformInto[RawUserEntry])
    }

    private def accountByCode(request: FindAccountByCode): Task[Option[RawAccount]] = {
      inline def query = quote {
        for {
          t <- tenants                          if t.active && t.deleted.isEmpty
          a <- accounts .join(_.tenant == t.id) if a.active && a.deleted.isEmpty && a.code == lift(request.code)
        } yield (t, a)
      }

      for {
        rows <- exec(run(query))
      } yield rows.headOption.map {
        case (tenant, account) => account.into[RawAccount].withFieldConst(_.tenant, tenant.id).withFieldConst(_.tenantCode, tenant.code).transform
      }
    }

    private def applicationDetailsGiven(request: FindApplications): Task[Seq[RawApplicationDetails]] = {

      inline def query = quote {
        for {
          ten <- tenants                                if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join(_.tenant == ten.id) if acc.deleted.isEmpty && acc.active && acc.code == lift(request.account)
          a2a <- account2app  .join(_.acc == acc.id)    if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)    if app.deleted.isEmpty && app.active
        } yield app
      }

      for {
        rows <- exec(run(query))
      } yield rows.map(_.transformInto[RawApplicationDetails])
    }

    private def applicationGiven(request: FindApplication): Task[Option[RawApplication]] = {

      def appFrom(row: ApplicationRow): Task[Option[RawApplication]] = {
        for {
          f1     <- groupsGiven(FindGroups(request.account, request.application)) .fork
          f2     <- rolesGiven (FindRoles (request.account, request.application)) .fork
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
          acc <- accounts     .join(_.tenant == ten.id)  if acc.deleted.isEmpty && acc.active && acc.code == lift(request.account)
          a2a <- account2app  .join(_.acc    == acc.id)  if a2a.deleted.isEmpty
          app <- applications .join(_.id     == a2a.app) if app.deleted.isEmpty && app.active && app.code == lift(request.application)
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

    private def addGroups(cmd: LinkUsersToGroups): Task[Unit] = {

      inline def insertValues(rows: Seq[UserToGroupRow]) = quote {
        liftQuery(rows).foreach(row => user2group.insertValue(row))
      }

      def rows(now: LocalDateTime) = for
        user  <- cmd.users
        group <- cmd.groups
      yield UserToGroupRow(usr = user, app = cmd.application, grp = group, created = now, deleted = None)

      for
        now  <- Clock.localDateTime
        _    <- exec(run(insertValues(rows(now))))
      yield ()
    }

    private def addRoles(request: LinkUsersToRoles): Task[Unit] = {
      def insertValues(rows: Seq[UserToRoleRow]) = quote {
        liftQuery(rows).foreach(row => user2role.insertValue(row))
      }

      def rows(now: LocalDateTime) = for
        user <- request.users
        role <- request.roles
      yield UserToRoleRow(usr = user, app = request.app, rid = role, created = now, deleted = None)

      for {
        now <- Clock.localDateTime
        _ <- exec(run(insertValues(rows(now))))
      } yield ()
    }

    private def setUserPin(request: DefineUserPin): Task[Unit] = {

      def row(now: LocalDateTime) = PinRow(
        id      = PinId.of(0),
        created = now,
        deleted = None,
        userId  = request.user ,
        pin     = request.pin
      )

      inline def stmt(row: PinRow) = quote {
        pins.insertValue(lift(row)).returning(_.id)
      }

      for {
        now <- Clock.localDateTime
        _   <- exec(run(stmt(row(now))))
      } yield ()
    }

    private def getUserPin(request: GetUserPin): Task[Option[Sha256Hash]] = {
      inline def query = quote {
        (for {
          p <- pins if p.deleted.isEmpty && p.userId == lift(request.user)
        } yield p).sortBy(_.created)(Ord.desc)
      }

      for {
        rows <- exec(run(query))
      } yield rows.headOption.map { _.pin }
    }

    private def usersByAccount(request: ReportUsersByAccount): Task[Map[RawAccount, Int]] = {
      inline def query = quote {
        (for {
          app <- applications                           if app.active && app.deleted.isEmpty && app.code == lift(request.app)
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

    private def usersGiven(request: FindUsersByCodes): Task[Seq[RawUserEntry]] = {
      inline def query = {
        quote {
          for {
            ten <- tenants                             if ten.deleted.isEmpty && ten.active
            acc <- accounts .join(_.tenant  == ten.id) if acc.deleted.isEmpty && acc.active && acc.id == lift(request.account)
            usr <- users    .join(_.account == acc.id) if usr.deleted.isEmpty && usr.active && liftQuery(request.codes).contains(usr.code)
          } yield usr
        }
      }

      for
        _    <- printQuery(query)
        rows <- exec(run(query))
      yield rows.map(_.transformInto[RawUserEntry])
    }
  }
}