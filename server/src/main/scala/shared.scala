package morbid

import zio.*

object config {

  import morbid.legacy.LegacyClientConfig

  import zio.config.*
  import zio.config.magnolia.*
  import zio.config.typesafe.*
  import Config.*

  case class JwtConfig(key: String, fake: Boolean)
  case class IdentityConfig(key: String, database: String, provisionSAMLUsers: Boolean)
  case class ClockConfig(timezone: String)
  case class MagicConfig(password: String)
  case class PinConfig(prefix: String, default: String)
  case class ServiceConfig(token: String)
  case class MorbidConfig(identities: IdentityConfig, jwt: JwtConfig, clock: ClockConfig, magic: MagicConfig, pin: PinConfig, legacy: LegacyClientConfig, printQueries: Boolean, service: ServiceConfig)

  object MorbidConfig {

    val layer = ZLayer {
      TypesafeConfigProvider.fromResourcePath(enableCommaSeparatedValueAsList = true).load(deriveConfig[MorbidConfig])
    }

    val legacy = ZLayer {
      for {
        cfg <- ZIO.service[MorbidConfig]
      } yield cfg.legacy
    }
  }
}

object utils {

  import domain.raw.RawUser
  import org.apache.commons.lang3.exception.ExceptionUtils
  import guara.errors.ReturnResponseWithExceptionError
  import zio.json.*
  import zio.http.{Body, Response, Header, Headers}
  import zio.http.Status.InternalServerError
  import zio.http.Request

  type ValidateToken = Request => Task[Unit]

  case class CommonError(
    origin  : String,
    code    : Int,
    message : String,
    request : Option[String] = None,
    trace   : Option[String] = None
  )

  given JsonCodec[CommonError] = DeriveJsonCodec.gen

  extension [T](task: Task[Option[T]])
    def orFail(message: String): Task[T] = {
      for
        maybe <- task
        value <- ZIO.fromOption(maybe).mapError(_ => Exception(message))
      yield value
    }

  extension [T](task: Task[T]) {
    def refineError(message: String): Task[T] = task.mapError(Exception(message, _))

    def errorToResponse(response: Response) = task.mapError(ReturnResponseWithExceptionError(_, response))

    def asCommonError(code: Int, msg: String) = {
      def response(error: Throwable) = Response(
        status  = InternalServerError,
        headers = Headers(Header.Custom("X-Error-Type", "GCEv0") /* Guara Common Error = GCEv0 */),
        body    = Body.fromString(CommonError(origin = "Morbid", code, message = msg, trace = Some(ExceptionUtils.getStackTrace(error))).toJson)
      )
      task.mapError(e => ReturnResponseWithExceptionError(e, response(e)))
    }
  }

  extension [T](op: Option[T])
    def orFail(message: String): Task[T] = ZIO.fromOption(op).mapError(_ => Exception(message))
}

object proto {

  import zio.json.*
  import types.*

  case class VerifyGoogleTokenRequest(token: String)
  case class VerifyMorbidTokenRequest(token: String)
  case class SetClaimsRequest(uid: String, claims: Map[String, String])
  case class GetLoginMode(email: Email, tenant: Option[TenantCode])
  case class EmitToken(email: Email, magic: Magic, days: Option[Int]) derives JsonCodec

  given JsonDecoder[VerifyGoogleTokenRequest] = DeriveJsonDecoder.gen
  given JsonDecoder[VerifyMorbidTokenRequest] = DeriveJsonDecoder.gen
  given JsonDecoder[SetClaimsRequest]         = DeriveJsonDecoder.gen
  given JsonDecoder[GetLoginMode]             = DeriveJsonDecoder.gen
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

  case class FindApplicationDetails(
    application: ApplicationCode
  ) extends Command[Option[RawApplicationDetails]]

  case class FindApplication(
    account     : AccountCode,
    application : ApplicationCode
  ) extends Command[Option[RawApplication]]

  case class LinkUsersToGroup(
    application : ApplicationId,
    group       : GroupId,
    users       : Seq[UserId]
  ) extends Command[Unit]

  case class UnlinkUsersFromGroup(
    application: ApplicationId,
    group      : GroupId,
    users      : Seq[UserId]
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

  case class FindAccountsByApp(app: ApplicationCode) extends Command[Seq[RawAccount]]
  case class FindUsersByApp   (app: ApplicationCode) extends Command[Seq[RawUserData]]

  case class FindUsersByCode(account: AccountId, codes: Seq[UserCode]) extends Command[Seq[RawUserEntry]]
  case class FindUserById(id: UserId) extends Command[Option[RawUser]]
  case class FindUserByEmail(email: Email) extends Command[Option[RawUser]]
  case class GetUserPin(user: UserId) extends Command[Option[Sha256Hash]]
  case class DefineUserPin(user: UserId, pin: Sha256Hash) extends Command[Unit]

  case class StoreAccount(
    id     : AccountId  , //Can't be 0
    tenant : TenantId   ,
    code   : AccountCode,
    name   : AccountName,
  ) extends Command[RawAccount]

  case class StoreUser(
    id      : UserId, // maybe 0
    email   : Email,
    code    : UserCode, // From firebase
    account : RawAccount,
    kind    : Option[UserKind] = None,
    update  : Boolean, //TODO: remove this as soon as we migrate all users from legacy,
    active  : Boolean,
  ) extends Command[RawUserEntry]

  case class StoreGroup(
    account     : AccountId,
    accountCode : AccountCode,
    application : RawApplication,
    group       : RawGroup,
    users       : Seq[UserCode],
    roles       : Seq[RoleCode]
  ) extends Command[RawGroup]

  case class LinkAccountToApp(
    acc: AccountId,
    app: ApplicationId,
  ) extends Command[Unit]

  case class LinkGroupToRoles(
    group : GroupId,
    roles : Seq[RoleId]
  ) extends Command[Unit]

  case class UnlinkGroupFromRoles(
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

  case class UsersByAccount(app: ApplicationCode, account: AccountId) extends Command[Seq[RawUserEntry]]
  case class UserExists(code: UserCode) extends Command[Boolean]

  case class RemoveAccount (code: AccountCode)                                   extends Command[Long]
  case class RemoveUser    (acc: AccountId, code: UserCode)                      extends Command[Long]
  case class RemoveGroup   (acc: AccountId, app: ApplicationId, code: GroupCode) extends Command[Long]
}