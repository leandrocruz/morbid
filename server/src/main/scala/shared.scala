package morbid

import zio.*

object config {

  import zio.config.*
  import zio.config.magnolia.*
  import zio.config.typesafe.*
  import Config.*

  case class JwtConfig(key: String, fake: Boolean)
  case class IdentityConfig(key: String, database: String, provisionSAMLUsers: Boolean)
  case class ClockConfig(timezone: String)
  case class MagicConfig(password: String)
  case class PinConfig(prefix: String)
  case class MorbidConfig(identities: IdentityConfig, jwt: JwtConfig, clock: ClockConfig, magic: MagicConfig, pin: PinConfig)

  object MorbidConfig {
    val layer = ZLayer {
      TypesafeConfigProvider.fromResourcePath(enableCommaSeparatedValueAsList = true).load(deriveConfig[MorbidConfig])
    }
  }
}

object utils {

  import domain.raw.RawUser
  import domain.simple.*
  import domain.mini.*
  import types.ApplicationCode
  import guara.errors.ReturnResponseWithExceptionError
  import zio.json.*
  import zio.http.Response

  val Morbid = ApplicationCode.of("morbid")

  extension (user: RawUser)
    def asJson(format: Option[String]): String = {
      format match {
        case Some("simple") => user.simple.toJson
        case Some("mini")   => user.mini.toJson
        case _              => user.toJson
      }
    }

  extension [T](task: Task[Option[T]])
    def orFail(message: String): Task[T] = {
      for
        maybe <- task
        value <- ZIO.fromOption(maybe).mapError(_ => Exception(message))
      yield value
    }

  extension [T](task: Task[T])
    def refineError(message: String): Task[T] = task.mapError(Exception(message, _))
    def errorToResponse(response: Response) = task.mapError(ReturnResponseWithExceptionError(_, response))

  extension [T](op: Option[T])
    def orFail(message: String): Task[T] = ZIO.fromOption(op).mapError(_ => Exception(message))
}

object proto {

  import zio.json.*
  import types.*
  import domain.UserKind

  case class VerifyGoogleTokenRequest(token: String)
  case class VerifyMorbidTokenRequest(token: String)
  case class ImpersonationRequest(email: Email, magic: Magic)
  case class SetClaimsRequest(uid: String, claims: Map[String, String])
  case class GetLoginMode(email: Email, tenant: Option[TenantCode])
  case class CreateUserApplication(application: ApplicationCode, groups: Seq[GroupCode])
  case class CreateUserRequest(email: Email, code: Option[UserCode] = None, password: Option[Password] = None, tenant: Option[TenantCode] = None, kind: Option[UserKind] = None, applications: Seq[CreateUserApplication])
  case class SetUserPin     (pin: Pin)
  case class ValidateUserPin(pin: Pin)

  given JsonDecoder[ImpersonationRequest]     = DeriveJsonDecoder.gen
  given JsonDecoder[VerifyGoogleTokenRequest] = DeriveJsonDecoder.gen
  given JsonDecoder[VerifyMorbidTokenRequest] = DeriveJsonDecoder.gen
  given JsonDecoder[SetClaimsRequest]         = DeriveJsonDecoder.gen
  given JsonDecoder[GetLoginMode]             = DeriveJsonDecoder.gen
  given JsonDecoder[CreateUserApplication]    = DeriveJsonDecoder.gen
  given JsonDecoder[CreateUserRequest]        = DeriveJsonDecoder.gen
  given JsonDecoder[SetUserPin]               = DeriveJsonDecoder.gen
  given JsonDecoder[ValidateUserPin]          = DeriveJsonDecoder.gen
}

object passwords {

  import types.Password
  import scala.util.Random

  trait PasswordGenerator {
    def generate: Task[Password]
  }

  private case class DefaultPasswordGenerator() extends PasswordGenerator {
    override def generate: Task[Password] =
      ZIO.attempt {
        Password.of {
          Random.alphanumeric.take(12).mkString("")
        }
      }
  }

  object PasswordGenerator {
    val layer: ZLayer[Any, Nothing, PasswordGenerator] = ZLayer.fromFunction(DefaultPasswordGenerator.apply _)
  }

}

object commands {

  import types.*
  import morbid.domain.*
  import morbid.domain.raw.*
  import java.time.LocalDateTime

  sealed trait Command[R]

  case class FindApplications(account: AccountCode) extends Command[Seq[RawApplicationDetails]]

  case class FindApplication(
    account     : AccountCode,
    application : ApplicationCode
  ) extends Command[Option[RawApplication]]

  case class LinkUsersToGroups(
    at          : LocalDateTime,
    application : ApplicationId,
    users       : Seq[UserId],
    groups      : Seq[GroupId]
  ) extends Command[Unit]

  case class FindGroups(
    account : AccountCode,
    apps    : Seq[ApplicationCode],
    filter  : Seq[GroupCode] = Seq.empty
  ) extends Command[Map[ApplicationCode, Seq[RawGroup]]]

  case class FindUsersInGroup(
    account : AccountCode,
    app     : ApplicationCode,
    group   : Option[GroupCode] = None
  ) extends Command[Seq[RawUserEntry]]

  case class FindUsersByCode(account: AccountId, codes: Seq[UserCode]) extends Command[Seq[RawUserEntry]]
  case class FindUserByEmail(email: Email) extends Command[Option[RawUser]]
  case class GetUserPin(user: UserId) extends Command[Option[Sha256Hash]]
  case class DefineUserPin(user: UserId, pin: Sha256Hash) extends Command[Unit]

  case class CreateUser(
    email   : Email,
    code    : UserCode,
    account : RawAccount,
    kind    : Option[UserKind] = None,
  ) extends Command[RawUser]

  case class StoreGroup(
    account     : AccountId,
    accountCode : AccountCode,
    application : RawApplication,
    group       : RawGroup,
    users       : Seq[UserCode],
    roles       : Seq[RoleCode]
  ) extends Command[RawGroup]

  case class LinkGroupToRoles(
    at    : LocalDateTime,
    app   : ApplicationId,
    group : GroupId,
    roles : Seq[RoleId]
  ) extends Command[Unit]

  case class FindRoles(
    account : AccountCode,
    app     : ApplicationCode
  ) extends Command[Seq[RawRole]]

  case class FindAccountByProvider(code: ProviderCode) extends Command[Option[RawAccount]]
  case class FindAccountByCode    (code: AccountCode)  extends Command[Option[RawAccount]]

  case class FindProviderByAccount(account: AccountId)                      extends Command[Option[RawIdentityProvider]]
  case class FindProviderByDomain(domain: Domain, code: Option[TenantCode]) extends Command[Option[RawIdentityProvider]]

  case class ReportUsersByAccount(app: ApplicationCode) extends Command[Map[RawAccount, Int]]
  case class UserExists(code: UserCode) extends Command[Boolean]
}