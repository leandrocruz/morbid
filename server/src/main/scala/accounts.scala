package morbid

import zio.*

object accounts {

  import morbid.commands.*
  import morbid.config.MorbidConfig
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.gip.*
  import morbid.legacy.*
  import morbid.pins.PinManager
  import morbid.proto.{SignupEmailTaken, SignupNameTaken, SignupRequest, UnknownUser}
  import morbid.repo.Repo
  import morbid.types.*
  import morbid.utils.*
  import org.apache.commons.lang3.RandomStringUtils

  import java.sql.SQLException
  import java.time.LocalDateTime
  import scala.util.Try

  trait AccountManager {
    def provision        (identity: CloudIdentity)          : Task[RawUser]
    def provisionFreemium(request: SignupRequest)           : Task[RawUser]
    def parseCSV         (account: RawAccount, csv: String) : Task[Seq[(Email, Try[RawUserEntry])]]
  }

  object AccountManager {
    val layer = ZLayer.fromFunction(LocalAccountManager.apply _)
  }

  case class LocalAccountManager(config: MorbidConfig, repo: Repo, legacyMorbid: LegacyMorbid, pins: PinManager, identities: Identities) extends AccountManager {

    private val DefaultGroup     = GroupCode.of("all")   //FIXME: this should not be here
    private val AdminGroup       = GroupCode.of("admin") //FIXME: this should not be here
    private val DefaultGroupName = GroupName.of("Todos") //FIXME: this should not be here
    private val AdminGroupName   = GroupName.of("Todos") //FIXME: this should not be here

    override def provision(identity: CloudIdentity): Task[RawUser] = {

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

        for {
          account <- repo.exec(FindAccountByProvider(id)).orFail(s"Can't find account for provider '$identity'")
          legacy  <- legacyUser(account)
          _       <- ZIO.logInfo(s"Provisioning user :: tenant:${account.tenant} account:${account.id}, uid:${legacy.id}, idp:$id, code:${identity.code}, email:${identity.email}")
          user    <- repo.exec(StoreUser(legacy.id, identity.email, identity.code, account, kind = None, update = false, active = true))
          _       <- setup(account, user)
          result  <- repo.exec(FindUserByEmail(user.email)).orFail(s"Error reading newly created user, email:${user.email}") // load applications, groups, etc
        } yield result
      }

      (identity.tenant, identity.kind, identity.provider) match
        case (None, ProviderKind.SAML, Some(id)) if config.identities.provisionSAMLUsers => provisionSaml(id)
        // Non-SAML identities (or SAML when provisioning is disabled) can no longer be
        // auto-provisioned via /login. Self-registered Free accounts must go through /signup.
        case _ => ZIO.fail(UnknownUser(identity.email))
    }

    /**
     * Provision a self-registered Free user under the existing DEFAULT tenant.
     *
     * Caller is responsible for verifying the Firebase ID token before invoking this.
     * Returns 409-mappable errors (SignupNameTaken / SignupEmailTaken) when the
     * unique constraints on (tenant, name) or globally on the user code are hit.
     */
    override def provisionFreemium(request: SignupRequest): Task[RawUser] = {

      def asNameTaken(err: Throwable): Throwable = err match
        case e: SQLException if e.getSQLState == "23505" => SignupNameTaken(request.account)
        case other                                       => other

      def asEmailTaken(err: Throwable): Throwable = err match
        case e: SQLException if e.getSQLState == "23505" => SignupEmailTaken(request.email)
        case other                                       => other

      def buildAccount(tenant: RawTenant, account: LegacyAccount) = {
        StoreAccount(
          id     = account.id,
          tenant = tenant.id,
          code   = AccountCode.of(s"freemium_${RandomStringUtils.secure.nextAlphanumeric(4)}"),
          name   = account.name,
          active = true,
          update = false
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
        now           <- Clock.localDateTime
        tenant        <- repo.exec(FindTenantByCode(request.tenant))                  .orFail(s"Tenant '${TenantCode.DEFAULT}' not found")
        details       <- repo.exec(FindApplicationDetails(request.application))       .orFail(s"Application '${request.application}' not found")
        plan          <- repo.exec(FindPlanByCode(request.application, request.plan)) .orFail(s"Plan '${request.plan}' not found for app '${request.application}'")
        legacyAccount <- legacyMorbid.createAccount(CreateLegacyAccountRequest(request.account, request.accountType))
        storeAccount  =  buildAccount(tenant, legacyAccount)
        account       <- repo.exec(storeAccount).mapError(asNameTaken)
        userRecord    <- identities.createUser(request.email, tenant.code, request.password)
        legacyUser    <- legacyMorbid.createUser(CreateLegacyUserRequest(account.id, request.name, request.email, request.userType))
        storeUser     =  buildUser(account, legacyUser, userRecord.getUid)
        user          <- repo.exec(storeUser).mapError(asEmailTaken)
        _             <- repo.exec(LinkAccountToApp (acc = account.id, app = details.id))
        _             <- repo.exec(LinkAccountToPlan(acc = account.id, plan = plan.id))
        application   <- repo.exec(FindApplication(account.code, details.code)).orFail(s"Application '${details.code}' for account '${account.id}' not found")
        groups        <- ZIO.foreach(request.groups) { linkGroup(now, account, application, user.code) }
        _             <- ZIO.logInfo(s"Provisioned Freemium account '${request.account}' (${account.id}) for user '${user.email}' under tenant ${tenant.code}")
        result        <- repo.exec(FindUserByEmail(user.email)).orFail(s"Error reading newly created user '${user.email}'")
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
  }
}