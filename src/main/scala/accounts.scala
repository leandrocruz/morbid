package morbid

import zio.*

object accounts {

  import morbid.types.*
  import morbid.repo.Repo
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.gip.*

  import java.time.LocalDateTime

  trait AccountManager {
    def userByEmail(email: Email): Task[Option[RawUser]]
    def provision(identity: CloudIdentity): Task[RawUser]
  }

  object AccountManager {
    val layer = ZLayer.fromFunction(LocalAccountManager.apply _)
  }

  case class LocalAccountManager(repo: Repo) extends AccountManager {

    override def provision(identity: CloudIdentity): Task[RawUser] = {

      def provisionSaml(id: ProviderCode): Task[RawUser] = {

        def build(account: RawAccount, created: LocalDateTime) = {
          RawUser(details = RawUserDetails(
              id          = 0.as[UserId],
              tenant      = account.tenant,
              tenantCode  = account.tenantCode,
              account     = account.id,
              accountCode = account.code,
              created     = created,
              active      = true,
              code        = identity.code,
              email       = identity.email
          ))
        }

        for {
          now     <- Clock.localDateTime
          maybe   <- repo.accountGiven(id)
          account <- ZIO.fromOption(maybe).mapError(_ => new Exception(s"Can't find account for provider '$identity'"))
          _       <- ZIO.logInfo(s"Provisioning user :: tenant:${account.tenant} account:${account.id}, idp:$id, code:${identity.code}, email:${identity.email}")
          user    <- repo.create(build(account, now))
          maybe   <- repo.userGiven(user.details.email)
          result  <- ZIO.fromOption(maybe).mapError(_ => new Exception(s"Error reading newly created user, email:${user.details.email}")) // load applications, groups, etc
        } yield result
      }

      (identity.tenant, identity.kind, identity.provider) match
        case (None, ProviderKind.SAML, Some(id)) => provisionSaml(id)
        case _                                   => ZIO.fail(new Exception(s"Can't create user for '${identity.email}' with '${identity.kind}' on '${identity.provider.getOrElse("NO PROVIDER")}'"))
    }

    override def userByEmail(email: Email): Task[Option[RawUser]] = repo.userGiven(email)
  }
}