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

  trait AccountManager {
    def provision(identity: CloudIdentity) : Task[RawUser]
  }

  object AccountManager {
    val layer = ZLayer.fromFunction(LocalAccountManager.apply _)
  }

  case class LocalAccountManager(config: MorbidConfig, repo: Repo) extends AccountManager {

    override def provision(identity: CloudIdentity): Task[RawUser] = {

      def provisionSaml(id: ProviderCode): Task[RawUser] = { //TODO: call the old morbid
        for {
          account <- repo.exec(FindAccountByProvider(id)).orFail(s"Can't find account for provider '$identity'")
          _       <- ZIO.logInfo(s"Provisioning user :: tenant:${account.tenant} account:${account.id}, idp:$id, code:${identity.code}, email:${identity.email}")
          user    <- repo.exec(StoreUser(UserId.of(0), identity.email, identity.code, account))
          result  <- repo.exec(FindUserByEmail(user.details.email)).orFail(s"Error reading newly created user, email:${user.details.email}") // load applications, groups, etc
        } yield result
      }

      (identity.tenant, identity.kind, identity.provider) match
        case (None, ProviderKind.SAML, Some(id)) if config.identities.provisionSAMLUsers => provisionSaml(id)
        case _ => ZIO.fail(new Exception(s"Can't create user for '${identity.email}' with '${identity.kind}' on '${identity.provider.getOrElse("NO PROVIDER")}'"))
    }
  }
}