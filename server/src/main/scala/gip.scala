package morbid

import zio.*

object gip {

  import morbid.repo.Repo
  import morbid.types.*
  import morbid.proto.*
  import morbid.config.*
  import morbid.domain.*
  import morbid.domain.raw.*
  import morbid.commands.*
  import morbid.utils.orFail

  import zio.json.*

  import scala.jdk.CollectionConverters.*
  import java.io.{FileInputStream, InputStream}
  import com.google.auth.oauth2.GoogleCredentials
  import com.google.firebase.{FirebaseApp, FirebaseOptions}
  import com.google.firebase.auth.FirebaseAuth
  import com.google.firebase.auth.FirebaseToken
  import com.google.firebase.auth.UserRecord
  import com.google.firebase.auth.UserRecord.CreateRequest
  import com.google.firebase.auth.ActionCodeSettings
  import com.google.firebase.auth.UserRecord.UpdateRequest

  sealed trait Identities {
    def passwordResetLink   (email: Email)                                         : Task[Link]
    def signInWithEmailLink (email: Email, url: String)                            : Task[Link]
    def changePassword      (email: Email, password: Password)                     : Task[Unit]
    def providerGiven       (email: Email, tenant: Option[TenantCode])             : Task[Option[RawIdentityProvider]]
    def providerGiven       (account: AccountId)                                   : Task[Option[RawIdentityProvider]]
    def verify              (req: VerifyGoogleTokenRequest)                        : Task[CloudIdentity]
    def claims              (req: SetClaimsRequest)                                : Task[Unit]
    def getUserByEmail      (email: Email, tenant: TenantCode)                     : Task[CloudUser]
    def createUser          (email: Email, tenant: TenantCode, password: Password) : Task[CloudUser]
  }

  case class CloudIdentity(
    issuer     : String,
    code       : UserCode,
    email      : Email,
    kind       : ProviderKind,
    provider   : Option[ProviderCode] = None,
    tenant     : Option[TenantCode]   = None,
    attributes : Map[String, String]  = Map.empty
  )

  trait CloudUser {
    def id   : String
    def email: String
  }

  given JsonEncoder[CloudIdentity] = DeriveJsonEncoder.gen[CloudIdentity]

  object Identities {

    val fake: ULayer[Identities] = ZLayer.succeed(FakeIdentities())

    val layer = ZLayer {

      def acquire(config: MorbidConfig) = ZIO.attempt(new FileInputStream(config.identities.key))

      def release(is: InputStream) = ZIO.succeed(is.close)

      def build(config: MorbidConfig, repo: Repo)(is: InputStream): Task[Identities] = {
        ZIO.attempt {

          val options = FirebaseOptions.builder()
            .setCredentials(GoogleCredentials.fromStream(is))
            .setDatabaseUrl(config.identities.database)
            .build()

          val app  = FirebaseApp.initializeApp(options)
          val auth = FirebaseAuth.getInstance(app)
          GoogleIdentities(auth, repo)
        }
      }

      for {
        config  <- ZIO.service[MorbidConfig]
        repo    <- ZIO.service[Repo]
        service <- ZIO.acquireReleaseWith(acquire(config))(release)(build(config, repo))
      } yield service
    }
  }

  private case class FakeIdentities() extends Identities {
    override def providerGiven(email: Email, tenant: Option[TenantCode]) = ZIO.none
    override def providerGiven(account: AccountId)                       = ZIO.none
    override def claims(req: SetClaimsRequest)                           = ZIO.unit
    override def verify             (req: VerifyGoogleTokenRequest)    = ZIO.fail(Exception("TODO: verify"))
    override def getUserByEmail     (email: Email, tenant: TenantCode) = ZIO.fail(Exception("TODO: getUserByEmail"))
    override def passwordResetLink  (email: Email)                     = ZIO.fail(Exception("TODO: passwordResetLink"))
    override def signInWithEmailLink(email: Email, url: String)        = ZIO.fail(Exception("TODO: signInWithEmailLink"))
    override def changePassword     (email: Email, password: Password) = ZIO.fail(Exception("TODO: changePassword"))

    override def createUser(eml: Email, tenant: TenantCode, password: Password) = {
      for
        rnd <- Random.nextIntBetween(0, 99)
      yield new CloudUser {
        override def id    = "usr" + rnd
        override def email = Email.value(eml)
      }
    }
  }

  private case class GoogleIdentities(auth: FirebaseAuth, repo: Repo) extends Identities {

    private def wrap(record: UserRecord): CloudUser = new CloudUser {
      override def id    = record.getUid
      override def email = record.getEmail
    }

    override def providerGiven(account: AccountId): Task[Option[RawIdentityProvider]] = {
      repo.exec(FindProviderByAccount(account))
    }

    override def providerGiven(email: Email, tenant: Option[TenantCode]): Task[Option[RawIdentityProvider]] = {
      email.domainName match
        case Some(domain) => repo.exec(FindProviderByDomain(domain, tenant))
        case _            => ZIO.succeed(None)
    }

    override def verify(req: VerifyGoogleTokenRequest) = {

      def build(token: FirebaseToken) = {
        CloudIdentity(
          issuer = token.getIssuer,
          code   = UserCode.of(token.getUid),
          email  = Email.of(token.getEmail),
          kind   = ProviderKind.UP,
          tenant = TenantCode.option(token.getTenantId),
        )
      }

      def valueFrom[T](token: FirebaseToken, key: String) = {
        val claims = token.getClaims.asScala.toMap

        val maybe = for {
          values <- claims.get("firebase").map(_.asInstanceOf[java.util.Map[String, AnyRef]].asScala.toMap)
          result <- values.get(key).map(_.asInstanceOf[T])
        } yield result

        maybe.orFail(s"Can't find value for key '$key'")
      }

      for {
        decoded    <- ZIO.attempt(auth.verifyIdToken(req.token))
        identity   <- ZIO.attempt(build(decoded))
        attributes <- valueFrom[java.util.Map[String, String]](decoded, "sign_in_attributes").map(_.asScala.toMap).orElse(ZIO.succeed(Map.empty))
        hint       <- valueFrom[String]                       (decoded, "sign_in_provider")
        provider   <- providerGiven(identity.email, identity.tenant)
      } yield identity.copy(
        kind       = provider.map(_.kind).getOrElse(ProviderKind.UP),
        provider   = provider.map(_.code),
        attributes = attributes
      )
    }

    override def claims(req: SetClaimsRequest) = {
      ZIO.attempt {
        auth.setCustomUserClaims(req.uid, req.claims.asJava)
      }
    }

    private def authGiven(code: Option[TenantCode]) = {
      code match
        case None | Some(TenantCode.DEFAULT) => auth
        case Some(value)                     => auth.getTenantManager.getAuthForTenant(TenantCode.value(value))
    }

    override def changePassword(email: Email, password: Password) = {
      ZIO.attemptBlockingIO {
        val record = auth.getUserByEmail(Email.value(email))
        val req    = new UpdateRequest(record.getUid).setPassword(Password.value(password))
        auth.updateUser(req)
      }
    }

    //See https://firebase.google.com/docs/auth/admin/manage-users
    override def createUser(email: Email, tenant: TenantCode, password: Password) = {
      val req = new CreateRequest()
        .setEmail    (Email.value(email))
        .setPassword (Password.value(password)  )
        .setDisabled (false)

      for
        record <- ZIO.attempt { authGiven(Some(tenant)).createUser(req) }
      yield wrap(record)
    }

    override def getUserByEmail(email: Email, tenant: TenantCode) = {
      for
        record <- ZIO.attempt { authGiven(Some(tenant)).getUserByEmail(Email.value(email)) }
      yield wrap(record)
    }

    override def passwordResetLink(email: Email) = {
      for
        link   <- ZIO.attempt { auth.generatePasswordResetLink(Email.value(email)) }.mapError(e => Exception(s"Error generating password reset link for '$email': ${e.getMessage}", e))
        result <- ZIO.fromOption(Option(link))                                      .mapError(_ => Exception(s"Failed to generate password reset link for '$email'"))
      yield Link.of(result)
    }

    override def signInWithEmailLink(email: Email, url: String) = {
      val settings = ActionCodeSettings
        .builder()
        .setUrl(url)
        .setHandleCodeInApp(true)
        .build()

      ZIO.attempt {
        Link.of {
          auth.generateSignInWithEmailLink(Email.value(email), settings)
        }
      }
    }
  }
}