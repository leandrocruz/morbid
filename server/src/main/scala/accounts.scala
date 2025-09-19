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
  import morbid.repo.Repo
  import morbid.types.*
  import morbid.utils.*
  import org.apache.commons.lang3.RandomStringUtils

  import java.time.LocalDateTime
  import scala.util.Try

  trait AccountManager {
    def provision(identity: CloudIdentity) : Task[RawUser]
    def parseCSV(account: RawAccount, csv: String): Task[Seq[(Email, Try[RawUserEntry])]]
  }

  object AccountManager {
    val layer = ZLayer.fromFunction(LocalAccountManager.apply _)
  }

  case class LocalAccountManager(config: MorbidConfig, repo: Repo, legacyMorbid: LegacyMorbid, pins: PinManager, identities: Identities) extends AccountManager {

    private val DefaultGroup = GroupCode.of("all")

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

          def create = legacyMorbid.create(CreateLegacyUserRequest(account = account.id, name = "Provisioned by Morbid", email = identity.email, `type` = "user"))

          for {
            maybe <- legacyMorbid.userBy(identity.email)
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
        case _ => ZIO.fail(new Exception(s"Can't provision user for '${identity.email}' with '${identity.kind}' on '${identity.provider.getOrElse("NO PROVIDER")}'"))
    }

    override def parseCSV(account: RawAccount, csv: String) = {

      def process(now: LocalDateTime)(line: String) = {

        def handle(email: Email, legacy: Option[LegacyUser], current: Option[RawUser]) = {

          def store(user: LegacyUser) = {

            for {
              fbUser <- identities.createUser(email, account.tenantCode, Password.of(RandomStringUtils.secure().nextAlphanumeric(10)))
              usr    <- repo.exec {
                StoreUser(
                  id      = user.id,
                  email   = email,
                  code    = UserCode.of(fbUser.getUid),
                  account = account,
                  kind    = None,
                  update  = false,
                  active  = true,
                )
              }
            } yield usr
          }

          (legacy, current) match
            case (None, _)             => ZIO.fail(Exception(s"Can't find legacy user '$email'"))
            case (Some(user), Some(_)) => ZIO.fail(Exception(s"User '$email' already exists"))
            case (Some(user), None)    => store(user)
        }

        val email = Email.of(line)
        for {
          legacy  <- legacyMorbid.userBy(email)
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