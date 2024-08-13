package morbid

import zio.*

object accounts {

  import morbid.config.MorbidConfig
  import morbid.commands.*
  import morbid.repo.Repo
  import morbid.types.*
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.gip.*
  import morbid.utils.*
  import morbid.legacy.*
  import morbid.pins.PinManager

  trait AccountManager {
    def provision(identity: CloudIdentity) : Task[RawUser]
  }

  object AccountManager {
    val layer = ZLayer.fromFunction(LocalAccountManager.apply _)
  }

  case class LocalAccountManager(config: MorbidConfig, repo: Repo, legacyMorbid: LegacyMorbid, pins: PinManager) extends AccountManager {

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
          user    <- repo.exec(StoreUser(legacy.id, identity.email, identity.code, account, kind = None, update = false))
          _       <- setup(account, user)
          result  <- repo.exec(FindUserByEmail(user.email)).orFail(s"Error reading newly created user, email:${user.email}") // load applications, groups, etc
        } yield result
      }

      (identity.tenant, identity.kind, identity.provider) match
        case (None, ProviderKind.SAML, Some(id)) if config.identities.provisionSAMLUsers => provisionSaml(id)
        case _ => ZIO.fail(new Exception(s"Can't provision user for '${identity.email}' with '${identity.kind}' on '${identity.provider.getOrElse("NO PROVIDER")}'"))
    }
  }
}