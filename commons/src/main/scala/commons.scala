package morbid

object types {

  import guara.utils.{safeCode, safeLatinName, safeDecode}
  import zio.json.JsonCodec
  import zio.json.{JsonEncoder, JsonDecoder, JsonFieldEncoder, JsonFieldDecoder}
  import scala.annotation.targetName

  opaque type TenantId        = Long
  opaque type AccountId       = Long
  opaque type UserId          = Long
  opaque type ApplicationId   = Long
  opaque type ProviderId      = Long
  opaque type GroupId         = Long
  opaque type RoleId          = Long
  opaque type PermissionId    = Long
  opaque type PinId           = Long
  opaque type TenantName      = String
  opaque type TenantCode      = String
  opaque type AccountName     = String
  opaque type AccountCode     = String
  opaque type ApplicationName = String
  opaque type ApplicationCode = String
  opaque type GroupName       = String
  opaque type GroupCode       = String
  opaque type RoleName        = String
  opaque type RoleCode        = String
  opaque type PermissionName  = String
  opaque type PermissionCode  = String
  opaque type ProviderName    = String
  opaque type ProviderCode    = String
  opaque type UserCode        = String
  opaque type Email           = String
  opaque type EmailUser       = String
  opaque type Pin             = String
  opaque type Sha256Hash      = String
  opaque type Password        = String
  opaque type Domain          = String
  opaque type Magic           = String
  opaque type Link            = String

  given JsonCodec[TenantId]      = JsonCodec.long
  given JsonCodec[AccountId]     = JsonCodec.long
  given JsonCodec[UserId]        = JsonCodec.long
  given JsonCodec[ApplicationId] = JsonCodec.long
  given JsonCodec[GroupId]       = JsonCodec.long
  given JsonCodec[RoleId]        = JsonCodec.long
  given JsonCodec[PermissionId]  = JsonCodec.long
  given JsonCodec[ProviderId]    = JsonCodec.long
  given JsonCodec[Password]      = JsonCodec.string

  // w = [a-zA-Z_0-9]

  private val domainFrom = ".+@(.+)"       .r
  private val userFrom   = "(.+)@.+"       .r
  private val domain     = "[\\w\\.\\-]+"  .r
  private val email      = "[\\w\\.\\-@]+" .r

  given JsonEncoder      [TenantName]      = JsonEncoder.string
  given JsonEncoder      [TenantCode]      = JsonEncoder.string
  given JsonEncoder      [AccountName]     = JsonEncoder.string
  given JsonEncoder      [AccountCode]     = JsonEncoder.string
  given JsonEncoder      [ApplicationName] = JsonEncoder.string
  given JsonEncoder      [ApplicationCode] = JsonEncoder.string
  given JsonEncoder      [GroupName]       = JsonEncoder.string
  given JsonEncoder      [GroupCode]       = JsonEncoder.string
  given JsonEncoder      [RoleName]        = JsonEncoder.string
  given JsonEncoder      [RoleCode]        = JsonEncoder.string
  given JsonEncoder      [PermissionName]  = JsonEncoder.string
  given JsonEncoder      [PermissionCode]  = JsonEncoder.string
  given JsonEncoder      [ProviderName]    = JsonEncoder.string
  given JsonEncoder      [ProviderCode]    = JsonEncoder.string
  given JsonEncoder      [UserCode]        = JsonEncoder.string
  given JsonEncoder      [Email]           = JsonEncoder.string
  given JsonEncoder      [Domain]          = JsonEncoder.string
  given JsonEncoder      [Magic]           = JsonEncoder.string
  given JsonEncoder      [Pin]             = JsonEncoder.string
  given JsonEncoder      [Link]             = JsonEncoder.string

  given JsonDecoder      [TenantName]      = safeLatinName(128)
  given JsonDecoder      [AccountName]     = safeLatinName(64)
  given JsonDecoder      [ApplicationName] = safeLatinName(256)
  given JsonDecoder      [GroupName]       = safeLatinName(64)
  given JsonDecoder      [RoleName]        = safeLatinName(32)
  given JsonDecoder      [PermissionName]  = safeLatinName(128)
  given JsonDecoder      [ProviderName]    = safeLatinName(256)

  given JsonDecoder      [TenantCode]      = safeCode(64)
  given JsonDecoder      [AccountCode]     = safeCode(16)
  given JsonDecoder      [ApplicationCode] = safeCode(16)
  given JsonDecoder      [GroupCode]       = safeCode(16)
  given JsonDecoder      [UserCode]        = safeCode(128)
  given JsonDecoder      [RoleCode]        = safeCode(16)
  given JsonDecoder      [PermissionCode]  = safeCode(16)
  given JsonDecoder      [ProviderCode]    = safeCode(128)

  given JsonDecoder      [Email]           = safeDecode(email, 256)
  given JsonDecoder      [Domain]          = safeDecode(domain, 256)
  given JsonDecoder      [Magic]           = JsonDecoder.string
  given JsonDecoder      [Pin]             = JsonDecoder.string
  given JsonDecoder      [Link]            = JsonDecoder.string

  given JsonFieldEncoder[ApplicationName] = JsonFieldEncoder.string
  given JsonFieldDecoder[ApplicationName] = JsonFieldDecoder.string
  given JsonFieldEncoder[ApplicationCode] = JsonFieldEncoder.string
  given JsonFieldDecoder[ApplicationCode] = JsonFieldDecoder.string
  given JsonFieldEncoder[RoleName]        = JsonFieldEncoder.string
  given JsonFieldDecoder[RoleName]        = JsonFieldDecoder.string
  given JsonFieldEncoder[RoleCode]        = JsonFieldEncoder.string
  given JsonFieldDecoder[RoleCode]        = JsonFieldDecoder.string

  trait OpaqueOps[N, T] {
    def of(n: N)     : T         = n.asInstanceOf[T]
    def value(t: T)  : N         = t.asInstanceOf[N]
    def option(n: N) : Option[T] = Option(n.asInstanceOf[T])
  }

  object AccountId       extends OpaqueOps[Long, AccountId]
  object AccountName     extends OpaqueOps[String, AccountName]
  object AccountCode     extends OpaqueOps[String, AccountCode]
  object ApplicationId   extends OpaqueOps[Long, ApplicationId]
  object ApplicationCode extends OpaqueOps[String, ApplicationCode]
  object ApplicationName extends OpaqueOps[String, ApplicationName]
  object Domain          extends OpaqueOps[String, Domain]
  object Email           extends OpaqueOps[String, Email]
  object EmailUser       extends OpaqueOps[String, EmailUser]
  object GroupCode       extends OpaqueOps[String, GroupCode]
  object GroupId         extends OpaqueOps[Long, GroupId]
  object GroupName       extends OpaqueOps[String, GroupName]
  object Link            extends OpaqueOps[String, Link]
  object Password        extends OpaqueOps[String, Password]
  object PinId           extends OpaqueOps[Long, PinId]
  object Pin             extends OpaqueOps[String, Pin]
  object PermissionId    extends OpaqueOps[Long, PermissionId]
  object PermissionCode  extends OpaqueOps[String, PermissionCode]
  object PermissionName  extends OpaqueOps[String, PermissionName]
  object ProviderCode    extends OpaqueOps[String, ProviderCode]
  object ProviderId      extends OpaqueOps[Long, ProviderId]
  object ProviderName    extends OpaqueOps[String, ProviderName]
  object RoleCode        extends OpaqueOps[String, RoleCode]
  object RoleId          extends OpaqueOps[Long, RoleId]
  object RoleName        extends OpaqueOps[String, RoleName]
  object Sha256Hash      extends OpaqueOps[String, Sha256Hash]
  object TenantCode      extends OpaqueOps[String, TenantCode] {
    val DEFAULT = TenantCode.of("DEFAULT")
  }
  object TenantId        extends OpaqueOps[Long, TenantId]
  object TenantName      extends OpaqueOps[String, TenantName]
  object UserCode        extends OpaqueOps[String, UserCode]
  object UserId          extends OpaqueOps[Long, UserId]

  extension (it: Email) {
    def domainName: Option[Domain] =
      it match {
        case domainFrom(value) => Some(Domain.of(value))
        case _                 => None
      }

    def userName: Option[EmailUser] =
      it match {
        case userFrom(value) => Some(EmailUser.of(value))
        case _ => None
      }
  }

  extension (it: Magic) {
    @targetName("magic") def string: String = it
    def is(value: String): Boolean = it == value
  }
}

object domain {

  import types.*
  import domain.token.SingleAppUser
  import zio.json.*
  import zio.optics.Lens
  import zio.json.internal.Write
  import java.time.{LocalDateTime, ZonedDateTime}

  trait HasEmail {
    def email: Email
  }

  enum UserKind {
    case RE /* Regular */ ,
         SA /* Service Account */
  }

  enum ProviderKind {
    case UP   /* Username and Password */ ,
         SAML /* SAML */
  }

  given JsonEncoder[UserKind]     = (kind: UserKind    , indent: Option[Int], out: Write) => out.write(s"\"${kind.toString}\"")
  given JsonEncoder[ProviderKind] = (kind: ProviderKind, indent: Option[Int], out: Write) => out.write(s"\"${kind.toString}\"")

  given JsonDecoder[UserKind]     = JsonDecoder[String](using JsonDecoder.string).map(UserKind.valueOf)
  given JsonDecoder[ProviderKind] = JsonDecoder[String](using JsonDecoder.string).map(ProviderKind.valueOf)

  object raw {

    import morbid.domain.token.CompactApplication
    import io.scalaland.chimney.dsl.*

    case class RawAccount(
      id         : AccountId,
      created    : LocalDateTime,
      deleted    : Option[LocalDateTime],
      tenant     : TenantId,
      tenantCode : TenantCode,
      active     : Boolean,
      code       : AccountCode,
      name       : AccountName,
    )

    case class RawUserEntry(
      id      : UserId,
      created : LocalDateTime,
      deleted : Option[LocalDateTime],
      account : AccountId,
      kind    : Option[UserKind],
      code    : UserCode,
      active  : Boolean,
      email   : Email
    )

    case class RawUser(
      details      : RawUserDetails,
      applications : Seq[RawApplication] = Seq.empty
    ) {
      def narrowTo(application: ApplicationCode): Option[SingleAppUser] = {
        applications
          .find(_.details.code == application)
          .map(app => SingleAppUser(details, app.transformInto[CompactApplication]))
      }
    }

    case class RawUserDetails(
      id          : UserId,
      created     : LocalDateTime,
      deleted     : Option[LocalDateTime] = None,
      tenant      : TenantId,
      tenantCode  : TenantCode,
      account     : AccountId,
      accountCode : AccountCode,
      kind        : Option[UserKind] = None,
      active      : Boolean,
      code        : UserCode,
      email       : Email
    )

    case class RawApplicationDetails(
      id      : ApplicationId,
      created : LocalDateTime,
      deleted : Option[LocalDateTime],
      active  : Boolean,
      code    : ApplicationCode,
      name    : ApplicationName,
    )

    case class RawApplication(
      details : RawApplicationDetails,
      groups  : Seq[RawGroup] = Seq.empty
    )

    case class RawIdentityProvider(
      id       : ProviderId,
      created  : LocalDateTime,
      deleted  : Option[LocalDateTime],
      account  : AccountId,
      active   : Boolean,
      domain   : Domain,
      kind     : ProviderKind, //SAML, UP, etc
      code     : ProviderCode,
      name     : ProviderName,
    )

    case class RawGroup(
      id      : GroupId,
      created : LocalDateTime,
      deleted : Option[LocalDateTime],
      code    : GroupCode,
      name    : GroupName,
      roles   : Seq[RawRole] = Seq.empty
    )

    case class RawPermission(
      id      : PermissionId,
      created : LocalDateTime,
      deleted : Option[LocalDateTime],
      code    : PermissionCode,
      name    : PermissionName,
    )

    case class RawRole(
      id          : RoleId,
      created     : LocalDateTime,
      deleted     : Option[LocalDateTime],
      code        : RoleCode,
      name        : RoleName,
      permissions : Seq[RawPermission] = Seq.empty
    )

    val userDetailsLens = Lens[RawUser, RawUserDetails](
      get = user => Right(user.details),
      set = details => user => Right(user.copy(details = details))
    )

    val idLens = Lens[RawUserDetails, UserId](
      get = details => Right(details.id),
      set = id => details => Right(details.copy(id = id))
    )

    given JsonCodec[RawApplicationDetails] = DeriveJsonCodec.gen
    given JsonCodec[RawApplication]        = DeriveJsonCodec.gen
    given JsonCodec[RawUserDetails]        = DeriveJsonCodec.gen
    given JsonCodec[RawGroup]              = DeriveJsonCodec.gen
    given JsonCodec[RawPermission]         = DeriveJsonCodec.gen
    given JsonCodec[RawRole]               = DeriveJsonCodec.gen
    given JsonCodec[RawUser]               = DeriveJsonCodec.gen
    given JsonCodec[RawUserEntry]          = DeriveJsonCodec.gen
    given JsonCodec[RawIdentityProvider]   = DeriveJsonCodec.gen
  }

  object token {

    import raw.*
    import io.scalaland.chimney.Transformer
    import io.scalaland.chimney.dsl.*

    opaque type RawToken = String

    object RawToken {
      def of(value: String): RawToken = value
      given JsonCodec[RawToken] = JsonCodec.string
    }

    extension (it: RawToken)
      def string: String = it

    trait HasRoles {
      def hasRole(code: RoleCode): Boolean
    }

    case class CompactGroup(
      code  : GroupCode,
      roles : Seq[RoleCode] = Seq.empty
    )

    case class CompactApplication(
      id     : ApplicationId,
      code   : ApplicationCode,
      groups : Seq[CompactGroup] = Seq.empty
    )

    case class CompactUser(
      details      : RawUserDetails,
      applications : Seq[CompactApplication] = Seq.empty
    )

//    case class CompactToken(
//      created        : ZonedDateTime,
//      expires        : Option[ZonedDateTime],
//      user           : CompactUser,
//      impersonatedBy : Option[RawUserDetails] = None
//    )

    case class Token(
      created        : ZonedDateTime,
      expires        : Option[ZonedDateTime],
      user           : CompactUser,
      impersonatedBy : Option[RawUserDetails] = None
    ) {
      private def roleByCode(code: RoleCode)(using app: ApplicationCode): Option[RoleCode] =
        for {
          a <- user.applications.find(_.code == app)
          r <- a.groups.flatMap(_.roles).find(_ == code)
        } yield r

      def hasRole(code: RoleCode)(using ApplicationCode) =
        roleByCode(code).isDefined

      def narrowTo(application: ApplicationCode): Option[SingleAppToken] =
        user
          .applications
          .find(_.code == application)
          .map { found =>
            SingleAppToken(
              created,
              expires,
              SingleAppUser(details = user.details, application = found, impersonatedBy = impersonatedBy)
            )
          }

      //def compact = this.transformInto[CompactToken]
    }
    case class SingleAppUser(
      details        : RawUserDetails,
      application    : CompactApplication,
      impersonatedBy : Option[RawUserDetails] = None
    )

    case class SingleAppToken(
      created : ZonedDateTime,
      expires : Option[ZonedDateTime],
      user    : SingleAppUser
    ) {
      def hasRole(code: RoleCode): Boolean = user.application.groups.flatMap(_.roles).contains(code)
    }

    given Transformer[RawGroup, CompactGroup]             = (original: RawGroup)       => CompactGroup(code = original.code, roles = original.roles.map(_.code))
    given Transformer[RawApplication, CompactApplication] = (original: RawApplication) => CompactApplication(id = original.details.id, code = original.details.code, groups = original.groups.map(_.transformInto[CompactGroup]))

    given JsonCodec[CompactGroup]       = DeriveJsonCodec.gen
    given JsonCodec[CompactApplication] = DeriveJsonCodec.gen
    given JsonCodec[CompactUser]        = DeriveJsonCodec.gen
    given JsonCodec[Token]              = DeriveJsonCodec.gen
    given JsonCodec[SingleAppUser]      = DeriveJsonCodec.gen
    given JsonCodec[SingleAppToken]     = DeriveJsonCodec.gen
  }

  object requests {
    case class StoreGroupRequest(id: Option[GroupId], code: Option[GroupCode], name: GroupName, users: Seq[UserCode], roles: Seq[RoleCode])
    case class StoreUserRequest(id: Option[UserId], code: Option[UserCode], kind: Option[UserKind], email: Email, password: Option[Password], tenant: Option[TenantCode], update: Option[Boolean] /* TODO: remove this as soon as we migrate all users from legacy */)
    case class RequestPasswordRequestLink(email: Email) extends HasEmail
    case class PasswordResetLink(link: Link)
    case class SetUserPin(email: Email, pin: Pin) extends HasEmail
    case class ValidateUserPin(pin: Pin)
    case class RemoveUserRequest(code: UserCode)
    case class RemoveGroupRequest(code: GroupCode)
    case class LoginViaEmailLinkRequest(email: Email, url: String)
    case class LoginViaEmailLinkResponse(link: Link)

    given JsonCodec[StoreGroupRequest]          = DeriveJsonCodec.gen
    given JsonCodec[StoreUserRequest]           = DeriveJsonCodec.gen
    given JsonCodec[RequestPasswordRequestLink] = DeriveJsonCodec.gen
    given JsonCodec[PasswordResetLink]          = DeriveJsonCodec.gen
    given JsonCodec[SetUserPin]                 = DeriveJsonCodec.gen
    given JsonCodec[ValidateUserPin]            = DeriveJsonCodec.gen
    given JsonCodec[RemoveUserRequest]          = DeriveJsonCodec.gen
    given JsonCodec[RemoveGroupRequest]         = DeriveJsonCodec.gen
    given JsonCodec[LoginViaEmailLinkRequest]   = DeriveJsonCodec.gen
    given JsonCodec[LoginViaEmailLinkResponse]  = DeriveJsonCodec.gen
  }
}

object roles {

  import types.{ApplicationCode, RoleCode}
  import domain.token.{Token, SingleAppToken, HasRoles}

  given Conversion[String, Role] with
    def apply(code: String): Role = SingleRole(RoleCode.of(code))

  sealed trait Role {
    def or  (code: String) : Role = or(SingleRole(RoleCode.of(code)))
    def or  (code: Role)   : Role = OrRole(this, code)
    def and (code: String) : Role = and(SingleRole(RoleCode.of(code)))
    def and (code: Role)   : Role = AndRole(this, code)

    def isSatisfiedBy(token: Token)(using ApplicationCode): Boolean
    def isSatisfiedBy(token: SingleAppToken): Boolean
  }

  private case class SingleRole(code: RoleCode) extends Role {
    override def toString = RoleCode.value(code)
    override def isSatisfiedBy(tk: Token)(using ApplicationCode): Boolean = tk.hasRole(code)
    override def isSatisfiedBy(tk: SingleAppToken)              : Boolean = tk.hasRole(code)
  }

  private case class OrRole(r1: Role, r2: Role) extends Role {
    override def toString = s"($r1 || $r2)"
    override def isSatisfiedBy(tk: Token)(using ApplicationCode): Boolean = r1.isSatisfiedBy(tk) || r2.isSatisfiedBy(tk)
    override def isSatisfiedBy(tk: SingleAppToken)              : Boolean = r1.isSatisfiedBy(tk) || r2.isSatisfiedBy(tk)
  }

  private case class AndRole(r1: Role, r2: Role) extends Role {
    override def toString = s"($r1 && $r2)"
    override def isSatisfiedBy(tk: Token)(using ApplicationCode): Boolean = r1.isSatisfiedBy(tk) && r2.isSatisfiedBy(tk)
    override def isSatisfiedBy(tk: SingleAppToken)              : Boolean = r1.isSatisfiedBy(tk) && r2.isSatisfiedBy(tk)
  }
}

object secure {

  import types.ApplicationCode
  import domain.token.{SingleAppToken, Token}
  import roles.Role
  import guara.utils.ensureResponse
  import guara.errors.*
  import zio.http.*
  import zio.*

  type AppRoute       = SingleAppToken ?=> Request => Task[Response]
  type TokenValidator = SingleAppToken => Either[String, Unit]

  val AllowAll: TokenValidator = _ => Right(())

  def role(role: Role, allow: TokenValidator = AllowAll)(fn: Request => Task[Response])(request: Request)(using token: SingleAppToken): Task[Response] = {

    def forbidden(message: String) = ZIO.fail(ReturnResponseError(Response.forbidden(message)))

    def test(token: SingleAppToken): Task[Unit] = {
      if (role.isSatisfiedBy(token)) ZIO.unit
      else                           forbidden(s"Required role '$role' is missing from user token (application: ${token.user.application.code})")
    }

    for {
      _ <- allow(token) match
             case Left(err) => forbidden(err)
             case Right(_)  => test(token)
      result <- fn(request)
    } yield result
  }

  def appRoute(application: ApplicationCode, tokenFrom: Request => Task[Token])(route: AppRoute)(request: Request): Task[Response] = {

    def execute(token: SingleAppToken) = {
      given SingleAppToken = token
      route(request)
    }

    ensureResponse {
      for
        _     <- ZIO.logInfo(s"Executing app route for app '${application}'")
        token <- tokenFrom(request)                         //.mapError(e => ReturnResponseError(Response.forbidden(s"Error extracting token from request: ${e.getMessage}")))
        _     <- ZIO.logInfo(s"Token extracted ${token.user.details.email}")
        sat   <- ZIO.fromOption(token.narrowTo(application)).mapError(_ => ReturnResponseError(Response.forbidden(s"User has no access to application '$application'")))
        _     <- ZIO.logInfo(s"Token narrowed. Executing")
        res   <- execute(sat)
      yield res
    }
  }

  private def sample(request: Request)(using SingleAppToken): Task[Response] = ???
  val test: AppRoute = role("") { _ => ZIO.succeed(Response.ok) }
  def tk(r: Request): Task[Token] = ???
  val x: (Request) => Task[Response] = appRoute(ApplicationCode.of(""), tk) { sample }
}
