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

  trait AccountManager {
    def provision(identity: CloudIdentity) : Task[RawUser]
  }

  object AccountManager {
    val layer = ZLayer.fromFunction(LocalAccountManager.apply _)
  }

  case class LocalAccountManager(config: MorbidConfig, repo: Repo, legacyMorbid: LegacyMorbid) extends AccountManager {

    private val Zero = UserId.of(0)
    private val DefaultGroup = GroupCode.of("all")

    override def provision(identity: CloudIdentity): Task[RawUser] = {

      def addUserToGroups(account: RawAccount, user: RawUserEntry): Task[Unit] = {

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
          apps   <- repo.exec(FindApplications(account.code))                                 //all apps
          groups <- repo.exec(FindGroups(account.code, apps.map(_.code), Seq(DefaultGroup)))  //all groups for these apps
          _      <- ZIO.foreach(apps) { link(groups) }                                        //add the user to the the 'all' group on each app
        } yield ()
      }

      def provisionSaml(id: ProviderCode): Task[RawUser] = {
        for {
          account <- repo.exec(FindAccountByProvider(id)).orFail(s"Can't find account for provider '$identity'")
          legacy  <- legacyMorbid.userBy(identity.email)
          uid     =  legacy.map(_.id).getOrElse(Zero)
          _       <- ZIO.logInfo(s"Provisioning user :: tenant:${account.tenant} account:${account.id}, uid:$uid, idp:$id, code:${identity.code}, email:${identity.email}")
          user    <- repo.exec(StoreUser(uid, identity.email, identity.code, account, kind = None, update = false))
          _       <- addUserToGroups(account, user)
          result  <- repo.exec(FindUserByEmail(user.email)).orFail(s"Error reading newly created user, email:${user.email}") // load applications, groups, etc
        } yield result
      }

      (identity.tenant, identity.kind, identity.provider) match
        case (None, ProviderKind.SAML, Some(id)) if config.identities.provisionSAMLUsers => provisionSaml(id)
        case _ => ZIO.fail(new Exception(s"Can't create user for '${identity.email}' with '${identity.kind}' on '${identity.provider.getOrElse("NO PROVIDER")}'"))
    }
  }
}