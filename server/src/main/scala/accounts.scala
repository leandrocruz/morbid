package morbid

import guara.errors.GuaraError
import zio.*

object accounts {

  import morbid.errors.*
  import morbid.MorbidError.*
  import morbid.commands.*
  import morbid.config.MorbidConfig
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.gip.*
  import morbid.legacy.*
  import morbid.pins.PinManager
  import morbid.domain.requests.{CreateAccount, ProvisionRequest}
  import morbid.repo.Repo
  import morbid.types.*
  import morbid.utils.*
  import com.google.firebase.auth.UserRecord
  import org.apache.commons.lang3.RandomStringUtils
  import io.scalaland.chimney.dsl.*
  import java.sql.SQLException
  import java.time.LocalDateTime
  import scala.util.Try

  trait AccountManager {
    def provisionSSO (identity: CloudIdentity)                       : Task[RawUser]
    def provision    (request: ProvisionRequest)                     : Task[RawUser]
    def create       (request: CreateAccount)(using ApplicationCode) : Task[Unit]
    def parseCSV     (account: RawAccount, csv: String)              : Task[Seq[(Email, Try[RawUserEntry])]]
  }

  object AccountManager {
    val layer = ZLayer.fromFunction(LocalAccountManager.apply _)
  }

  case class LocalAccountManager(config: MorbidConfig, repo: Repo, legacyMorbid: LegacyMorbid, pins: PinManager, identities: Identities) extends AccountManager {

    private val DefaultGroup     = GroupCode.of("all")   //FIXME: this should not be here
    private val AdminGroup       = GroupCode.of("admin") //FIXME: this should not be here
    private val DefaultGroupName = GroupName.of("Todos") //FIXME: this should not be here
    private val AdminGroupName   = GroupName.of("Admin") //FIXME: this should not be here

    override def provisionSSO(identity: CloudIdentity): Task[RawUser] = {

      def provisionSaml(id: ProviderCode): Task[RawUser] = {

        def setup(account: RawAccount, user: RawUserEntry): Task[Unit] = {

          def link(groupsByApp: Map[ApplicationCode, Seq[RawGroup]])(app: RawApplicationDetails): Task[Unit] = {

            def build = LinkUsersToGroup(app.id, _, Seq(user.id))

            val maybe = for {
              groups <- groupsByApp.get(app.code)
              group  <- groups.find(_.code == DefaultGroup)
            } yield group

            maybe match
              case None        => ZIO.unit
              case Some(group) =>
                for {
                  _ <- ZIO.logInfo(s"Adding user '${user.email}' to group '${group.code} (${group.id})' in app '${app.id}'")
                  _ <- repo.exec(build(group.id))
                } yield ()
          }

          for {
            _      <- pins.set(user.id, Pin.of(config.pin.default)).mapError(err => Exception(s"Error setting default user PIN: ${err.getMessage}", err))
            apps   <- repo.exec(FindApplications(account.code))                                 //all apps
            groups <- repo.exec(FindGroups(account.code, apps.map(_.code), Seq(DefaultGroup)))  //all groups for these apps
            _      <- ZIO.foreach(apps) { link(groups) }                                        //add the user to the the 'all' group on each app
          } yield ()
        }

        def legacyUser(account: RawAccount): Task[LegacyUser] = {

          def create = legacyMorbid.createUser(CreateLegacyUserRequest(account = account.id, name = "Provisioned by Morbid", email = identity.email, `type` = "user"))

          for {
            maybe <- legacyMorbid.userByEmail(identity.email)
            user  <- maybe.map(ZIO.succeed).getOrElse(create)
          } yield user
        }

        for
          account <- repo.exec(FindAccountByProvider(id)).orFail(AccountNotFound, s"Can't find account for provider '$identity'")
          legacy  <- legacyUser(account)
          _       <- ZIO.logInfo(s"Provisioning user :: tenant:${account.tenant} account:${account.id}, uid:${legacy.id}, idp:$id, code:${identity.code}, email:${identity.email}")
          user    <- repo.exec(StoreUser(legacy.id, identity.email, identity.code, account, kind = None, update = false, active = true))
          _       <- setup(account, user)
          result  <- repo.exec(FindUserByEmail(user.email)).orFail(UserNotFound, s"Error reading newly created user, email:${user.email}") // load applications, groups, etc
        yield result
      }

      (identity.tenant, identity.kind, identity.provider) match
        case (None, ProviderKind.SAML, Some(id)) if config.identities.provisionSAMLUsers => provisionSaml(id)
        case _                                                                           => GuaraError.fail(AccountError, s"Can't provision account for '${identity.email}'")
    }

    /**
     * Provision a self-registered Free user under the existing DEFAULT tenant.
     */
    override def provision(request: ProvisionRequest): Task[RawUser] = {

      case class LegacyContext(tenant: RawTenant, legacyAccount: LegacyAccount, legacyUser: LegacyUser, userRecord: UserRecord, details: RawApplicationDetails, plan: RawPlan)

      // External calls (Firebase, legacy morbid) happen *before* the DB transaction because
      // they cannot be rolled back. If the DB tx later fails, legacy/Firebase entries become
      // orphans — compensation is a separate concern (see callers / cleanup jobs).
      def prepareLegacy: Task[LegacyContext] = {
        for
          tenant        <- repo.exec(FindTenantByCode(request.tenant))                  .orFail(TenantNotFound     , s"Tenant '${request.tenant}' not found")
          details       <- repo.exec(FindApplicationDetails(request.application))       .orFail(ApplicationNotFound, s"Application '${request.application}' not found")
          plan          <- repo.exec(FindPlanByCode(request.application, request.plan)) .orFail(PlanNotFound       , s"Plan '${request.plan}' not found for app '${request.application}'")
          legacyAccount <- legacyMorbid.createAccount(CreateLegacyAccountRequest(request.account, request.accountType, request.identifier))
          userRecord    <- identities.createUser(request.email, tenant.code, request.password)
          legacyUser    <- legacyMorbid.createUser(CreateLegacyUserRequest(legacyAccount.id, request.name, request.email, request.userType))
        yield LegacyContext(tenant, legacyAccount, legacyUser, userRecord, details, plan)
      }

      def provisionWith(ctx: LegacyContext) = {

        // Distinguish the specific unique constraint that fired. Without the constraint
        // name check, *any* 23505 (PK collision on accounts.id, accounts.code collision,
        // users PK collision, etc.) would masquerade as "name_taken" or "identifier_taken"
        // or "email_taken". Other 23505s propagate as the original SQLException so the
        // real cause stays visible.
        def asIdentifierTaken(err: Throwable): Throwable = err match
          case e: SQLException if e.getSQLState == "23505" && e.getMessage.contains("accounts_identifier_key") => request.identifier.map(IdentifierTakenException(_, e)).getOrElse(e)
          case other => other

        def asEmailTaken(err: Throwable): Throwable = err match
          case e: SQLException if e.getSQLState == "23505" && e.getMessage.contains("users_account_email_key") => EmailTakenException(request.email, e)
          case other => other

        def buildAccount(tenant: RawTenant, account: LegacyAccount) = {
          StoreAccount(
            id         = account.id,
            tenant     = tenant.id,
            code       = AccountCode.of(s"freemium_${RandomStringUtils.secure.nextAlphanumeric(4)}"),
            name       = account.name,
            active     = true,
            update     = false,
            identifier = request.identifier
          )
        }

        def buildUser(account: RawAccount, user: LegacyUser, code: String) = {
          StoreUser(
            id      = user.id,
            email   = request.email,
            code    = UserCode.of(code),
            account = account,
            kind    = None,
            update  = false,
            active  = true,
          )
        }

        def linkGroup(now: LocalDateTime, account: RawAccount, application: RawApplication, user: UserCode)(code: GroupCode, roleCodes: Seq[RoleCode]): Task[(GroupCode, RawGroup)] = {

          def build(roles: Seq[RawRole]) = {
            val name = if code == AdminGroup then AdminGroupName else DefaultGroupName

            val group = RawGroup(
              id      = GroupId.of(0),
              created = now,
              deleted = None,
              code    = code,
              name    = name,
              roles   = roles.filter(roleCodes.contains)
            )

            StoreGroup(account = account.id, accountCode = account.code, application = application, group = group, users = Seq(user), roles = roleCodes)
          }

          for
            roles <- repo.exec(FindRoles(account = account.code, app = application.details.code))
            store =  build(roles)
            group <- repo.exec(store)
          yield (code, group)
        }

        for
          now         <- Clock.localDateTime
          account     <- repo.exec(buildAccount(ctx.tenant, ctx.legacyAccount))              .mapError(asIdentifierTaken)
          user        <- repo.exec(buildUser(account, ctx.legacyUser, ctx.userRecord.getUid)).mapError(asEmailTaken)
          _           <- repo.exec(LinkAccountToApp (acc = account.id, app = ctx.details.id))
          _           <- repo.exec(LinkAccountToPlan(acc = account.id, plan = ctx.plan.id))
          application <- repo.exec(FindApplication(account.code, ctx.details.code)).orFail(ApplicationNotFound, s"Application '${ctx.details.code}' for account '${account.id}' not found")
          _           <- ZIO.foreach(request.groups) { linkGroup(now, account, application, user.code) }
          reloaded    <- repo.exec(FindUserByEmail(user.email)).orFail(UserNotFound, s"Error reading newly created user '${user.email}'")
        yield reloaded

      }

      val tag = s"${request.accountType} account '${request.account}' for user '${request.email}' under tenant '${request.tenant}'"
      for
        _      <- ZIO.logInfo(s"Provisioning $tag")
        ctx    <- prepareLegacy
        result <- repo.transaction { provisionWith(ctx) }
        _      <- ZIO.logInfo(s"Provisioned $tag")
      yield result
    }

    override def parseCSV(account: RawAccount, csv: String) = {

      def process(now: LocalDateTime)(line: String) = {

        def handle(email: Email, legacy: Option[LegacyUser], current: Option[RawUser]) = {

          def store(user: LegacyUser) = {

            def userGiven(code: UserCode) = {
              StoreUser(
                id      = user.id,
                email   = email,
                code    = code,
                account = account,
                kind    = None,
                update  = false,
                active  = true,
              )
            }

            for
              fbUser <- identities.createUser(email, account.tenantCode, Password.of(RandomStringUtils.secure().nextAlphanumeric(10)))
              usr    <- repo.exec(userGiven(UserCode.of(fbUser.getUid)))
            yield usr
          }

          (legacy, current) match
            case (None, _)             => ZIO.fail(Exception(s"Can't find legacy user '$email'"))
            case (Some(user), Some(_)) => ZIO.fail(Exception(s"User '$email' already exists"))
            case (Some(user), None)    => store(user)
        }

        val email = Email.of(line).toLowerCase
        for {
          legacy  <- legacyMorbid.userByEmail(email)
          current <- repo.exec(FindUserByEmail(email))
          result  <- handle(email, legacy, current).either
        } yield (email, result.toTry)
      }

      for {
        now     <- Clock.localDateTime
        entries <- ZIO.foreachPar(csv.split("\n")) { process(now) }
      } yield entries
    }

    override def create(req: CreateAccount)(using appCode: ApplicationCode) = {

      def ensureGroup(code: GroupCode, name: GroupName, app: RawApplication, acc: RawAccount): Task[RawGroup] = {
        val roles = if(code == GroupCode.admin) Seq(RoleCode.of("adm")) else Seq.empty
        for
          now    <- Clock.localDateTime
          group  =  RawGroup(GroupId.of(0), now, None, code, name, Seq.empty)
          result <- repo.exec {
            StoreGroup(
              account     = acc.id,
              accountCode = acc.code,
              application = app,
              group       = group,
              users       = Seq.empty,
              roles       = roles
            )
          }
        yield result
      }

      def ensureApp: Task[RawApplication] = {
        for
          maybe   <- repo.exec(FindApplicationDetails(appCode))
          details <- ZIO.fromOption(maybe).mapError(_ => Exception(s"Can't find application '$appCode'"))
        yield RawApplication(details)
      }

      def ensureAccount(req: CreateAccount): Task[RawAccount] = {

        def create = {
          ZIO.logInfo(s"Account '${req.id}' does not exist yet. Creating one") *>
          repo.exec {
            req
              .into[StoreAccount]
              .withFieldConst(_.active, true)
              .withFieldConst(_.update, false)
              .transform
          }
        }

        for
          maybe  <- repo.exec(FindAccountById(req.id))
          result <- maybe.map(ZIO.succeed).getOrElse(create)
        yield result
      }

      def ensureUser(req: CreateAccount, acc: RawAccount): Task[RawUserEntry] = {

        def create = {

          def fbCreate = identities.createUser(req.email, acc.tenantCode, Password.of(RandomStringUtils.secure().nextAlphanumeric(10)))

          for
            _      <- ZIO.logInfo(s"User '${req.user}' does not exist yet. Creating one")
            maybe  <- identities.getUserByEmail(req.email, acc.tenantCode).either
            fbUser <- maybe.map(ZIO.succeed).getOrElse(fbCreate)
            cmd    =  StoreUser(id = req.user, email = req.email.toLowerCase, code = UserCode.of(fbUser.getUid), account = acc, kind = None, update = false, active = true)
            user   <- repo.exec(cmd)
          yield user
        }

        def toEntry(raw: RawUser): Task[RawUserEntry] = {
          ZIO.succeed {
            raw.details.transformInto[RawUserEntry]
          }
        }

        for
          maybe  <- repo.exec(FindUserById(req.user))
          result <- maybe.map(toEntry).getOrElse(create)
        yield result
      }

      for
        _       <- ZIO.logInfo(s"Creating Account for '${req.email}'")
        app     <- ensureApp
        acc     <- ensureAccount(req)
        user    <- ensureUser(req, acc)
        admin   <- ensureGroup(GroupCode.admin, GroupName.of("Admin"), app, acc)
        all     <- ensureGroup(GroupCode.all  , GroupName.of("Todos"), app, acc)
        _       <- repo.exec(LinkAccountToApp(acc = acc.id,  app = app.details.id))
        _       <- repo.exec(LinkUsersToGroup(application = app.details.id, group = admin.id, users = Seq(user.id)))
        _       <- repo.exec(LinkUsersToGroup(application = app.details.id, group = all  .id, users = Seq(user.id)))
      yield ()
    }
  }
}