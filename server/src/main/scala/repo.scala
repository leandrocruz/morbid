package morbid

import zio.*

object repo {

  import commands.*
  import types.*
  import domain.*
  import domain.raw.*
  import io.getquill.*
  import io.getquill.jdbczio.Quill
  import io.scalaland.chimney.dsl.*
  import morbid.config.MorbidConfig
  import utils.refineError

  import java.sql.SQLException
  import java.time.LocalDateTime
  import javax.sql.DataSource

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
    deleted : Option[LocalDateTime] = None
  )

  private case class GroupToRoleRow(
    grp     : GroupId,
    rid     : RoleId,
    created : LocalDateTime,
    deleted : Option[LocalDateTime] = None
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
    
    def get[R](command: Command[Option[R]])(msg: => String): Task[R] = {
      for {
        result <- exec(command)
        value  <- ZIO.fromOption(result).mapError(_ => Exception(msg))
      } yield value
    }
  }

  object Repo {

    val datasource: ZLayer[Any, Throwable, DataSource] = Quill.DataSource.fromPrefix("database")

    val layer: ZLayer[MorbidConfig & DataSource, Throwable, Repo] = ZLayer.fromZIO {
      for {
        cfg <- ZIO.service[MorbidConfig]
        ds  <- ZIO.service[DataSource]
      } yield DatabaseRepo(cfg, ds)
    }
  }

  private case class DatabaseRepo(config: MorbidConfig, ds: DataSource) extends Repo {

    import ctx._
    import extras._
    
    private type ApplicationGroups = (ApplicationId, GroupRow)
    private type AppMap[T]         = Map[ApplicationCode, Seq[T]]

    private lazy val ctx = new PostgresZioJdbcContext(SnakeCase)

    private inline given InsertMeta[TenantRow]           = insertMeta[TenantRow]           (_.id)
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
    private inline def group2role   = quote { querySchema[GroupToRoleRow]      ("group_to_role")      }
    private inline def roles        = quote { querySchema[RoleRow]             ("roles")              }
    private inline def permissions  = quote { querySchema[PermissionRow]       ("permissions")        }
    private inline def providers    = quote { querySchema[IdentityProviderRow] ("identity_providers") }

    private def exec[T](zio: ZIO[DataSource, SQLException, T]): Task[T] = zio.provide(ZLayer.succeed(ds))

    override def exec[R](command: Command[R]): Task[R] = {
      command match
        case r: StoreAccount           => storeAccount(r)
        case r: StoreGroup             => storeGroup(r)
        case r: StoreUser              => storeUser(r)
        case r: DefineUserPin          => setUserPin(r)
        case r: GetUserPin             => getUserPin(r)
        case r: FindAccountByCode      => accountByCode(r)
        case r: FindAccountById        => accountById(r)
        case r: FindAccountByProvider  => accountByProvider(r)
        case r: FindApplication        => applicationGiven(r)
        case r: FindApplicationDetails => applicationDetails(r)
        case r: FindApplications       => applicationDetailsGiven(r)
        case r: FindGroups             => groupsGiven(r)
        case r: FindProviderByAccount  => providerGiven(r)
        case r: FindProviderByDomain   => providerGiven(r)
        case r: FindRoles              => rolesGiven(r)
        case r: FindUsersByCode        => usersGiven(r)
        case r: FindUsersByApp         => usersByApp(r)
        case r: FindAccountsByApp      => accountsByApp(r)
        case r: FindUserByEmail        => userGiven(r)
        case r: FindUserById           => userGiven(r)
        case r: FindUsersInGroup       => usersGiven(r)
        case r: LinkAccountToApp       => linkAccountToApp(r)
        case r: LinkUsersToGroup       => linkGroups(r)
        case r: UnlinkUsersFromGroup   => ZIO.fail(Exception("TODO"))
        case r: LinkGroupToRoles       => ZIO.fail(Exception("TODO"))
        case r: UnlinkGroupFromRoles   => ZIO.fail(Exception("TODO"))
        case r: RemoveAccount          => removeAccount(r)
        case r: RemoveGroup            => removeGroup(r)
        case r: RemoveUser             => removeUser(r)
        case r: UsersByAccount         => usersByAccount(r)
        case r: UserExists             => userExists(r)
    }

    private def userGiven(request: FindUserByEmail | FindUserById): Task[Option[RawUser]] = {

      def filterUser = request match
        case FindUserById(id)       => quote { users.filter { usr => usr.active && usr.deleted.isEmpty && usr.id    == lift(id)    } }
        case FindUserByEmail(email) => quote { users.filter { usr => usr.active && usr.deleted.isEmpty && usr.email == lift(email) } }

      inline def userQuery = quote {
        for {
          usr <- filterUser
          acc <- accounts     .join(_.id  == usr.account) if acc.active && acc.deleted.isEmpty
          ten <- tenants      .join(_.id  == acc.tenant)  if ten.active && ten.deleted.isEmpty
          a2a <- account2app  .join(_.acc == acc.id)      if a2a.deleted.isEmpty
          app <- applications .join(_.id  == a2a.app)     if app.active && app.deleted.isEmpty
        } yield (ten, acc, usr, app)
      }

      def asRawUser(rows: Seq[(TenantRow, AccountRow, UserRow, ApplicationRow)]): Task[Option[RawUser]] = {

        def build(tenant: TenantRow, account: AccountRow, user: UserRow, ignored: ApplicationRow) = {
          val details = user
           .into[RawUserDetails]
           .withFieldConst(_.tenant, account.tenant)
           .withFieldConst(_.tenantCode, tenant.code)
           .withFieldConst(_.accountCode, account.code)
           .transform
          val apps = rows.map(_._4).distinct.map(_.transformInto[RawApplicationDetails]).map(RawApplication(_))
          RawUser(details = details, applications = apps)
        }

        ZIO.attempt {
          rows.headOption.map(build)
        }
      }

      def groupsFor(user: RawUser): Task[Map[ApplicationId, Seq[RawGroup]]] = {

        def merge(rows: Seq[(GroupRow, Option[RoleRow])]): Map[ApplicationId, Seq[RawGroup]] = {

          def bind(group: GroupRow, roles: Seq[Option[RoleRow]]) = {

            val seq = roles
              .filter(_.isDefined)
              .map(_.get)
              .map(_.into[RawRole].withFieldConst(_.permissions, Seq.empty).transform)

            (
              group.app,
              group
                .into[RawGroup]
                .withFieldConst(_.roles, seq)
                .transform
            )
          }

          rows
            .groupMap(_._1)(_._2)
            .toSeq
            .map(bind)
            .groupMap(_._1)(_._2)
        }

        inline def query = quote {
          for {
            u2g <- user2group                                           if u2g.usr == lift(user.details.id) && u2g.deleted.isEmpty
            grp <- groups     .join    (_.id  == u2g.grp)               if grp.deleted.isEmpty
            g2r <- group2role .leftJoin(_.grp == grp.id)                if g2r.exists(_.deleted.isEmpty)
            rol <- roles      .leftJoin(r => g2r.exists(_.rid == r.id)) if rol.exists(_.deleted.isEmpty)
          } yield (grp, rol)
        }

        for {
          _    <- printQuery(query)
          rows <- exec(run(query))
        } yield merge(rows)
      }

      def assign(groups: Map[ApplicationId, Seq[RawGroup]])(application: RawApplication) = {
        application.copy(groups = groups.getOrElse(application.details.id, Seq.empty))
      }

      for {
        _      <- printQuery(userQuery)
        rows   <- exec(run(userQuery))
        maybe  <- asRawUser(rows)
        result <- maybe match
          case None      => ZIO.succeed(None)
          case Some(usr) =>
            for {
              groups <- groupsFor(usr)
            } yield Some(usr.copy(applications = usr.applications.map(assign(groups))))
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

    private def storeAccount(request: StoreAccount): Task[RawAccount] = {

      def build(now: LocalDateTime, tenant: RawTenant) = RawAccount(
        id         = request.id,
        created    = now,
        deleted    = None,
        tenant     = tenant.id,
        tenantCode = tenant.code,
        active     = true,
        code       = request.code,
        name       = request.name
      )

      def store(raw: RawAccount): Task[RawAccount] = {

        def insertWithId(row: AccountRow) = {
          inline def stmt = quote { accounts.insertValue(lift(row)) }
          for
            _ <- ZIO.log(s"Creating new account '${row.name}' with id ${row.id}")
            _ <- exec(run(stmt))
          yield raw
        }

        def insertWithoutId(row: AccountRow) = {
          inline given InsertMeta[AccountRow] = insertMeta[AccountRow](_.id)
          inline def stmt = quote { accounts.insertValue(lift(row)).returning(_.id) }
          for
            _  <- ZIO.log(s"Creating new account '${row.name}'")
            id <- exec(run(stmt))
          yield raw.copy(id = id)
        }

        def update(row: AccountRow) = {
          inline def stmt = quote {
            accounts.filter(_.id == lift(row.id))
              .update(
                _.name    -> lift(row.name),
                _.deleted -> lift(row.deleted),
                _.active  -> lift(row.active)
              )
          }

          for
            _ <- ZIO.log(s"Updating account '${row.id}' - '${row.name}'")
            _ <- exec(run(stmt))
          yield raw
        }

        val row = raw.into[AccountRow].transform

        (request.update, AccountId.value(request.id) == 0) match
          case (true , true)  => ZIO.fail(Exception(s"Update without AccountId")) // Force exception
          case (true , false) => update(row)
          case (false, false) => insertWithId(row)
          case (false, true)  => insertWithoutId(row)
      }

      def tenantById: Task[Option[RawTenant]] = {
        inline def stmt = quote { tenants.filter(t => t.id == lift(request.tenant) && t.active && t.deleted.isEmpty) }
        for
          rows <- exec(run(stmt))
        yield rows.headOption.map(_.transformInto[RawTenant])
      }

      for {
        now    <- Clock.localDateTime
        maybe  <- tenantById
        tenant <- ZIO.fromOption(maybe).mapError(_ => Exception(s"Tenant '${request.tenant}' not found"))
        raw    =  build(now, tenant)
        acc    <- store(raw)
      } yield acc
    }

    private def storeUser(req: StoreUser): Task[RawUserEntry] = {

      def build(created: LocalDateTime) = {
        RawUserEntry(
          id      = req.id,
          created = created,
          deleted = None,
          account = req.account.id,
          kind    = req.kind,
          code    = req.code,
          active  = req.active,
          email   = req.email,
        )
      }

      def store(raw: RawUserEntry): Task[RawUserEntry] = {
        val row = raw.transformInto[UserRow]

        def insertWithoutId = {

          inline given InsertMeta[UserRow] = insertMeta[UserRow](_.id)
          inline def stmt = quote { users.insertValue(lift(row)).returning(_.id) }

          for {
            _  <- ZIO.log(s"Creating new user '${row.email}'")
            id <- exec(run(stmt))
          } yield raw.copy(id = id)
        }

        def insertWithId = {
          inline def stmt = quote { users.insertValue(lift(row)) }
          for
            _ <- ZIO.log(s"Creating new user '${row.email}' with id ${row.id}")
            _ <- exec(run(stmt))
          yield raw
        }

        def update = {
          inline def stmt = quote {
            users.filter(_.id == lift(row.id)).update(_.email -> lift(row.email), _.deleted -> lift(row.deleted), _.active -> lift(row.active))
          }
          for
            _ <- ZIO.log(s"Updating user '${row.email}' id ${row.id}")
            _ <- exec(run(stmt))
          yield raw
        }

        (req.update, UserId.value(req.id) == 0) match
          case (true, true)   => ZIO.fail(Exception(s"Update without UserId")) // Force exception
          case (true, false)  => update
          case (false, false) => insertWithId
          case (false, true)  => insertWithoutId
       }

      for {
        now <- Clock.localDateTime
        raw =  build(now)
        usr <- store(raw)
      } yield usr

    }

    private def removeUser(request: RemoveUser): Task[Long] = {

      def remove(now: Option[LocalDateTime]) = {
        inline def stmt = quote {
          users.filter(u => u.account == lift(request.acc) && u.code == lift(request.code)).update(_.deleted -> lift(now))
        }

        for
          _     <- ZIO.log(s"Removing user '${request.code}' from account '${request.acc}'")
          count <- exec(run(stmt))
          _     <- ZIO.when(count != 1) { ZIO.fail(Exception(s"Error removing user '${request.code}' (count: $count)"))}
        yield count
      }

      for {
        now    <- Clock.localDateTime
        result <- remove(Some(now))
      } yield result

    }

    private def removeAccount(request: RemoveAccount): Task[Unit] = {

      def remove(now: Option[LocalDateTime]) = {
        inline def stmt = quote {
          accounts
            .filter(_.id == lift(request.id))
            .update(_.deleted -> lift(now))
        }

        for
          count <- exec(run(stmt))
          _     <- ZIO.when(count != 1) { ZIO.fail(Exception(s"Error removing account '${request.id}'")) }
        yield ()
      }

      for
        now    <- Clock.localDateTime
        result <- remove(Some(now))
      yield ()
    }

    private def storeGroup(request: StoreGroup): Task[RawGroup] = {

      val accId   = request.account
      val accCode = request.accountCode
      val appId   = request.application.details.id
      val appCode = request.application.details.code

      def findExistingGroup: Task[Option[RawGroup]] = {
        if (GroupId.value(request.group.id) > 0) groupsGiven(FindGroups(accCode, Seq(appCode), Seq(request.group.code))).map(_.getOrElse(appCode, Seq.empty).headOption)
        else                                     ZIO.succeed(None)
      }

      def store(existing: Option[RawGroup]): Task[RawGroup] = {

        def create = {

          val row = request
            .group
            .into[GroupRow]
            .withFieldConst(_.app, appId)
            .withFieldConst(_.acc, accId)
            .transform

          inline def stmt = quote {
            groups.insertValue(lift(row)).returning(_.id)
          }

          for
            id <- exec(run(stmt))
          yield request.group.copy(id = id)
        }

        def update(group: RawGroup) = {

          inline def stmt = quote {
            groups.filter(_.id == lift(group.id)).update(_.name -> lift(request.group.name))
          }

          for
            _ <- exec(run(stmt))
          yield group.copy(name = request.group.name)
        }

        existing match
          case None        => create
          case Some(group) => update(group)
      }

      def queryUsers = usersGiven(FindUsersByCode(accId, request.users))
      def queryRoles = rolesGiven(FindRoles(accCode, appCode))

      def handleUsers(group: RawGroup, existing: Option[RawGroup], all: Seq[RawUserEntry]): Task[Unit] = {

        def retrieveCurrent: Task[Seq[RawUserEntry]] = {
          existing match
            case None      => ZIO.succeed(Seq.empty)
            case Some(old) => usersGiven(FindUsersInGroup(accCode, appCode, Some(old.code)))
        }

        for
          current   <- retrieveCurrent
          wanted    =  all.filter(user => request.users.contains(user.code))
          intersect =  wanted.intersect(current)
          toAdd     =  wanted.diff(intersect)
          toRemove  =  current.diff(intersect)
          _         <- ZIO.when(toAdd.nonEmpty)    { linkGroups   (LinkUsersToGroup    (appId, group.id, toAdd   .map(_.id))) }
          _         <- ZIO.when(toRemove.nonEmpty) { unlinkGroups (UnlinkUsersFromGroup(appId, group.id, toRemove.map(_.id))) }
        yield ()
      }

      def handleRoles(group: RawGroup, existing: Option[RawGroup], all: Seq[RawRole]): Task[Seq[RawRole]] = {

        val current   = existing.map(_.roles).getOrElse(Seq.empty)
        val wanted    = all.filter(role => request.roles.contains(role.code))
        val intersect = wanted.intersect(current)
        val toAdd     = wanted.diff(intersect)
        val toRemove  = current.diff(intersect)

        for
          _ <- ZIO.when(toAdd.nonEmpty)    { addRoles (LinkGroupToRoles    (group.id, toAdd   .map(_.id))) }
          _ <- ZIO.when(toRemove.nonEmpty) { delRoles (UnlinkGroupFromRoles(group.id, toRemove.map(_.id))) }
        yield wanted
      }

      for
        existing <- findExistingGroup
        group    <- store(existing)                           .refineError(s"Error storing group '${request.group.name}' (${request.group.id}/${request.group.code})")
        users    <- queryUsers                                .refineError("Error searching for account users")
        appRoles <- queryRoles                                .refineError("Error searching for account roles")
        _        <- handleUsers   (group, existing, users)    .refineError("Error linking users to group"     )
        roles    <- handleRoles   (group, existing, appRoles) .refineError("Error linking roles to group"     )
      yield group.copy(roles = roles)
    }

    private def removeGroup(request: RemoveGroup): Task[Long] = {

      def remove(now: Option[LocalDateTime]) = {
        inline def stmt = quote {
          groups.filter(g => g.acc == lift(request.acc) && g.app == lift(request.app) && g.code == lift(request.code)).update(_.deleted -> lift(now))
        }

        for
          _     <- ZIO.log(s"Removing group '${request.code}' from application '${request.app}' from account '${request.acc}'")
          count <- exec(run(stmt))
          _     <- ZIO.when(count != 1) { ZIO.fail(Exception(s"Error removing group '${request.code}' (count: $count)"))}
        yield count
      }

      for {
        now    <- Clock.localDateTime
        result <- remove(Some(now))
      } yield result

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

      val code = request.code.getOrElse(TenantCode.DEFAULT)

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

    private def groupsGiven(request: FindGroups): Task[Map[ApplicationCode, Seq[RawGroup]]] = {

      def merge(rows: Seq[(ApplicationRow, (GroupRow, (Option[RoleRow], Option[PermissionRow])))]): Map[ApplicationCode, Seq[RawGroup]] = {

        def groupByFirstElement[A, B](seq: Seq[(A, B)]): Seq[(A, Seq[B])] = seq.groupBy(_._1).view.mapValues(_.map(_._2)).toSeq

        def toGroup(group: GroupRow, roles: Seq[(Option[RoleRow], Option[PermissionRow])]): RawGroup = {

          val groupRoles = groupByFirstElement {
            roles.filter(_._1.isDefined).map(it => (it._1.get, it._2))
          } map {
            case (role, perms) =>
              val discarded = perms.filter(_.isDefined).map(_.get).map(_.transformInto[RawPermission])
              role.into[RawRole].withFieldConst(_.permissions, Seq.empty).transform
          }

          group
            .into[RawGroup]
            .withFieldConst(_.roles, groupRoles)
            .transform
        }

        groupByFirstElement {
          groupByFirstElement(rows).flatMap {
            case (app: ApplicationRow, groups) => groupByFirstElement(groups).map {
              case (group: GroupRow, roles) =>
                (app.code, toGroup(group, roles))
            }
          }
        }.toMap
      }

      inline def query = quote {
        for {
          ten <- tenants                                                if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join    (_.tenant == ten.id)             if acc.deleted.isEmpty && acc.active && acc.code == lift(request.account)
          a2a <- account2app  .join    (_.acc == acc.id)                if a2a.deleted.isEmpty
          app <- applications .join    (_.id == a2a.app)                if app.deleted.isEmpty && app.active && liftQuery(request.apps).contains(app.code)
          grp <- groups       .join    (_.app == a2a.app)               if grp.deleted.isEmpty && grp.acc == acc.id && (lift(request.filter.isEmpty) || liftQuery(request.filter).contains(grp.code))
          g2r <- group2role   .leftJoin(_.grp == grp.id)                if g2r.exists(_.deleted.isEmpty)
          rol <- roles        .leftJoin(r => g2r.exists(_.rid == r.id)) if rol.exists(_.deleted.isEmpty)
          per <- permissions  .leftJoin(p => rol.exists(_.id == p.rid)) if per.exists(_.deleted.isEmpty)
        } yield (app, (grp, (rol, per)))
      }

      for {
        _    <- printQuery(query)
        rows <- exec(run(query))
      } yield merge(rows)
    }

    private def rolesGiven(request: FindRoles): Task[Seq[RawRole]] = {

      def toRole(role: RoleRow, data: Seq[(RoleRow, Option[PermissionRow])]): RawRole = {
        val discarded = data.map(_._2).filter(_.isDefined).map(_.get).distinct.map(_.transformInto[RawPermission])
        role.into[RawRole].withFieldConst(_.permissions, Seq.empty).transform
      }

      inline def query = quote {
        for {
          ten <- tenants                                 if ten.deleted.isEmpty && ten.active
          acc <- accounts     .join(_.tenant == ten.id)  if acc.deleted.isEmpty && acc.active && acc.code == lift(request.account)
          a2a <- account2app  .join(_.acc == acc.id)     if a2a.deleted.isEmpty
          app <- applications .join(_.id == a2a.app)     if app.deleted.isEmpty && app.active && app.code == lift(request.app)
          rol <- roles        .join(_.app == app.id)     if rol.deleted.isEmpty
          per <- permissions  .leftJoin(_.rid == rol.id) if per.exists(_.deleted.isEmpty)
        } yield (rol, per)
      }

      for {
        rows <- exec(run(query))
      } yield rows.groupBy(_._1).map(toRole).toSeq
    }

    private inline def printQuery[T](inline quoted: Quoted[Query[T]]): Task[Unit] = {
      if(config.printQueries) {
        for {
          str <- exec(ctx.translate(quoted, prettyPrint = false))
          _   <- ZIO.log(str)
        } yield ()
      } else ZIO.unit
    }

    private def accountsByAppFilter(code: ApplicationCode) = quote {
      for
        app <- applications if app.code == lift(code)
        ata <- account2app.join(_.app == app.id)
        acc <- accounts.join(_.id == ata.acc)
      yield acc
    }

    private def accountsByApp(request: FindAccountsByApp): Task[Seq[RawAccount]] = {

      inline def query = quote {
        for
          acc <- accountsByAppFilter(request.app)
          ten <- tenants.join(_.id == acc.tenant)
        yield (ten, acc)
      }

      for
        rows <- exec(run(query))
      yield rows.map {
        (tenant, account) => account.into[RawAccount].withFieldConst(_.tenantCode, tenant.code).transform
      }
    }

    private def usersByApp(request: FindUsersByApp): Task[Seq[RawUserData]] = {

      inline def groupsByUser(user: UserRow) = {
        quote {
          for
            ata <- user2group.join(_.usr == user.id)
            grp <- groups    .join(_.id == ata.grp)
          yield grp
        }
      }

      inline def query = {
        quote {
          for
            acc  <- accountsByAppFilter(request.app)
            usr  <- users.join(_.account == acc.id)
            grps <- groupsByUser(usr)
          yield (usr, grps)
        }
      }

      for
        rows <- exec(run(query))
      yield rows.groupBy { (user, _) => user }.view.mapValues { data => data.map { (_, grp) => grp} }.toMap.map {
        (usr, groups) => usr.into[RawUserData].withFieldConst(_.groups, groups.map(_.into[RawGroup].withFieldConst(_.roles, Seq.empty).transform)).transform
      }.toSeq
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
            usr <- users        .join(_.id     == u2g.usr) if usr.deleted.isEmpty
          } yield usr
        }
      }

      inline def appUsers = {
        quote {
          for {
            ten <- tenants                                 if ten.deleted.isEmpty && ten.active
            acc <- accounts     .join(_.tenant == ten.id)  if acc.deleted.isEmpty && acc.active && acc.code == lift(request.account)
            usr <- users        .join(_.account == acc.id) if usr.deleted.isEmpty
          } yield usr
        }
      }

      inline def query = request.group match
        case Some(code) => groupUsers(code)
        case None       => appUsers

      for {
        //_    <- printQuery(query)
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

    private def accountById(request: FindAccountById): Task[Option[RawAccount]] = {
      inline def query = quote {
        for
          ten <- tenants                         if ten.active && ten.deleted.isEmpty
          acc <- accounts.join(_.tenant == ten.id) if acc.active && acc.deleted.isEmpty && acc.id == lift(request.id)
        yield (ten, acc)
      }

      for
        rows <- exec(run(query))
      yield rows.headOption.map {
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
          groups <- groupsGiven(FindGroups(request.account, Seq(request.application)))
        } yield Some(RawApplication(
          details = row.transformInto[RawApplicationDetails],
          groups  = groups.getOrElse(request.application, Seq.empty),
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

    private def applicationDetails(request: FindApplicationDetails): Task[Option[RawApplicationDetails]] = {
      inline def query = quote {
        for {
          app <- applications if app.deleted.isEmpty && app.active && app.code == lift(request.application)
        } yield app
      }

      for
        rows <- exec(run(query))
      yield rows.headOption.map(_.transformInto[RawApplicationDetails])
    }

    private def linkAccountToApp(request: LinkAccountToApp): Task[Unit] = {

      inline def stmt(row: AccountToAppRow) = quote {
        account2app.insertValue(lift(row))
      }

      for
        now <- Clock.localDateTime
        row =  AccountToAppRow(request.acc, request.app, now, None)
        _   <- exec(run(stmt(row)))
      yield ()
    }

    private def linkGroups(cmd: LinkUsersToGroup): Task[Unit] = {

      inline def insertValues(rows: Seq[UserToGroupRow]) = quote {
        liftQuery(rows).foreach(row => user2group.insertValue(row))
      }

      def rows(now: LocalDateTime) = cmd.users.map { user =>
          UserToGroupRow(
          usr     = user,
          app     = cmd.application,
          grp     = cmd.group,
          created = now,
        )
      }

      for
        now   <- Clock.localDateTime
        _     <- exec(run(insertValues(rows(now))))
      yield ()
    }

    private def unlinkGroups(cmd: UnlinkUsersFromGroup): Task[Long] = {

      inline def stmt = quote {
        user2group.filter { u2g =>
          u2g.app == lift(cmd.application) &&
          u2g.grp == lift(cmd.group)       &&
          liftQuery(cmd.users).contains(u2g.usr)
        }.delete
      }

      exec(run(stmt))
    }

    private def addRoles(cmd: LinkGroupToRoles): Task[Unit] = {
      def insertValues(rows: Seq[GroupToRoleRow]) = quote {
        liftQuery(rows).foreach(row => group2role.insertValue(row))
      }

      def rows(now: LocalDateTime) = {
        cmd.roles.map { rid =>
          GroupToRoleRow(
            grp     = cmd.group,
            rid     = rid,
            created = now,
          )
        }
      }

      for
        now <- Clock.localDateTime
        _ <- exec(run(insertValues(rows(now))))
      yield ()
    }

    private def delRoles(cmd: UnlinkGroupFromRoles): Task[Long] = {

      inline def stmt = quote {
        group2role.filter { g2r => g2r.grp == lift(cmd.group) && liftQuery(cmd.roles).contains(g2r.rid) }.delete
      }

      exec(run(stmt))
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
        } yield p).sortBy(_.created)(using Ord.desc)
      }

      for {
        rows <- exec(run(query))
      } yield rows.headOption.map { _.pin }
    }

    private def usersByAccount(request: UsersByAccount): Task[Seq[RawUserEntry]] = {
      inline def query = quote {
        for
          app <- applications                           if app.active && app.deleted.isEmpty && app.code == lift(request.app)
          a2a <- account2app .join(_.app == app.id)     if               a2a.deleted.isEmpty && a2a.acc == lift(request.account)
          acc <- accounts    .join(_.id == a2a.acc)     if acc.active && acc.deleted.isEmpty
          usr <- users       .join(_.account == acc.id) if usr.active && usr.deleted.isEmpty
        yield usr
      }

      for
        rows <- exec(run(query))
      yield rows.map(_.transformInto[RawUserEntry])
    }

    private def usersGiven(request: FindUsersByCode): Task[Seq[RawUserEntry]] = {
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