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
    def passwordResetLink   (email: Email)                                : Task[Link]
    def signInWithEmailLink (email: Email, url: String)                   : Task[Link]
    def changePassword      (email: Email, password: Password)            : Task[Unit]
    def providerGiven(email: Email, tenant: Option[TenantCode])           : Task[Option[RawIdentityProvider]]
    def providerGiven(account: AccountId)                                 : Task[Option[RawIdentityProvider]]
    def verify     (req: VerifyGoogleTokenRequest)                        : Task[CloudIdentity]
    def claims     (req: SetClaimsRequest)                                : Task[Unit]
    def createUser (email: Email, tenant: TenantCode, password: Password) : Task[UserRecord]
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

  given JsonEncoder[CloudIdentity] = DeriveJsonEncoder.gen[CloudIdentity]

  object Identities {
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

  private case class GoogleIdentities(auth: FirebaseAuth, repo: Repo) extends Identities {

    override def providerGiven(account: AccountId): Task[Option[RawIdentityProvider]] = {
      repo.exec(FindProviderByAccount(account))
    }

    override def providerGiven(email: Email, tenant: Option[TenantCode]): Task[Option[RawIdentityProvider]] = {
      email.domainName match
        case Some(domain) => repo.exec(FindProviderByDomain(domain, tenant))
        case _            => ZIO.succeed(None)
    }

    override def verify(req: VerifyGoogleTokenRequest): Task[CloudIdentity] = {

      def build(token: FirebaseToken) = {
        CloudIdentity(
          issuer = token.getIssuer,
          code   = UserCode.of(token.getUid),
          email  = Email.of(token.getEmail),
          kind   = ProviderKind.UP,
          tenant = TenantCode.option(token.getTenantId),
        )
      }

      def valueFrom[T](token: FirebaseToken, key: String): Task[T] = {
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

    override def claims(req: SetClaimsRequest): Task[Unit] = {
      ZIO.attempt {
        auth.setCustomUserClaims(req.uid, req.claims.asJava)
      }
    }

    private def authGiven(code: Option[TenantCode]) = {
      code match
        case None | Some(TenantCode.DEFAULT) => auth
        case Some(value)                     => auth.getTenantManager.getAuthForTenant(TenantCode.value(value))
    }

    override def changePassword(email: Email, password: Password): Task[Unit] = {
      ZIO.attemptBlockingIO {
        val record = auth.getUserByEmail(Email.value(email))
        val req    = new UpdateRequest(record.getUid).setPassword(Password.value(password))
        auth.updateUser(req)
      }
    }

    //See https://firebase.google.com/docs/auth/admin/manage-users
    override def createUser(email: Email, tenant: TenantCode, password: Password): Task[UserRecord] = {
      val req = new CreateRequest()
        .setEmail    (Email.value(email))
        .setPassword (Password.value(password)  )
        .setDisabled (false)

      ZIO.attempt { authGiven(Some(tenant)).createUser(req) }
    }

    override def passwordResetLink(email: Email): Task[Link] = {
      for
        link   <- ZIO.attempt { auth.generatePasswordResetLink(Email.value(email)) }.mapError(e => Exception(s"Error generating password reset link for '$email': ${e.getMessage}", e))
        result <- ZIO.fromOption(Option(link))                                      .mapError(_ => Exception(s"Failed to generate password reset link for '$email'"))
      yield Link.of(result)
    }

    override def signInWithEmailLink(email: Email, url: String): Task[Link] = {
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