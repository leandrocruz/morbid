package morbid.admin.api

import morbid.domain.UserKind
import morbid.types.*
import zio.json.*

import java.time.LocalDateTime

/* auth */

case class LoginRequest(firebaseToken: String)
case class LoginResponse(email: Email, account: AccountId, name: Option[String])

enum LoginMode {
  case up, saml
}

case class GetProviderRequest(email: Email)

case class GetProviderResponse(
  `type` : LoginMode,
  id     : Option[String],
  name   : Option[String],
)

/* accounts */

case class AccountResponse(
  id      : AccountId,
  code    : AccountCode,
  name    : AccountName,
  tenant  : TenantId,
  active  : Boolean,
  created : LocalDateTime,
)

case class CreateAccountBody(
  tenant : TenantId,
  code   : AccountCode,
  name   : AccountName,
  active : Boolean,
)

case class UpdateAccountBody(
  name   : AccountName,
  active : Boolean,
)

/* users */

case class UserResponse(
  id      : UserId,
  code    : UserCode,
  email   : Email,
  active  : Boolean,
  kind    : Option[UserKind],
  account : AccountId,
  created : LocalDateTime,
)

case class CreateUserBody(
  email  : Email,
  kind   : Option[UserKind] = None,
  active : Boolean = true,
)

case class UpdateUserBody(
  email  : Email,
  active : Boolean,
)

case class ChangePasswordBody(
  email    : Email,
  password : Password,
)

case class SetPinBody(
  email : Email,
  pin   : Pin,
)

case class PasswordResetBody(
  email : Email,
)

case class PasswordResetResponse(
  link : Link,
)

/* groups */

case class GroupResponse(
  id     : GroupId,
  code   : GroupCode,
  name   : GroupName,
  roles  : List[RoleCode],
)

case class CreateGroupBody(
  code  : Option[GroupCode],
  name  : GroupName,
  users : List[UserCode] = List.empty,
  roles : List[RoleCode] = List.empty,
)

/* applications */

case class ApplicationResponse(
  id      : ApplicationId,
  code    : ApplicationCode,
  name    : ApplicationName,
  active  : Boolean,
  created : LocalDateTime,
)

case class CreateApplicationBody(
  code : ApplicationCode,
  name : ApplicationName,
)

case class UpdateApplicationBody(
  id     : ApplicationId,
  name   : ApplicationName,
  active : Boolean,
)

/* roles */

case class RoleResponse(
  id   : RoleId,
  code : RoleCode,
  name : RoleName,
)

object codecs {

  given JsonEncoder[LoginMode] = JsonEncoder.string.contramap(_.toString)
  given JsonDecoder[LoginMode] = JsonDecoder.string.mapOrFail {
    case "up"   => Right(LoginMode.up)
    case "saml" => Right(LoginMode.saml)
    case other  => Left(s"Unknown LoginMode: $other")
  }

  given JsonCodec[LoginRequest]           = DeriveJsonCodec.gen
  given JsonCodec[LoginResponse]          = DeriveJsonCodec.gen
  given JsonCodec[GetProviderRequest]     = DeriveJsonCodec.gen
  given JsonCodec[GetProviderResponse]    = DeriveJsonCodec.gen
  given JsonCodec[AccountResponse]        = DeriveJsonCodec.gen
  given JsonCodec[CreateAccountBody]      = DeriveJsonCodec.gen
  given JsonCodec[UpdateAccountBody]      = DeriveJsonCodec.gen
  given JsonCodec[UserResponse]           = DeriveJsonCodec.gen
  given JsonCodec[CreateUserBody]         = DeriveJsonCodec.gen
  given JsonCodec[UpdateUserBody]         = DeriveJsonCodec.gen
  given JsonCodec[ChangePasswordBody]     = DeriveJsonCodec.gen
  given JsonCodec[SetPinBody]             = DeriveJsonCodec.gen
  given JsonCodec[PasswordResetBody]      = DeriveJsonCodec.gen
  given JsonCodec[PasswordResetResponse]  = DeriveJsonCodec.gen
  given JsonCodec[GroupResponse]          = DeriveJsonCodec.gen
  given JsonCodec[CreateGroupBody]        = DeriveJsonCodec.gen
  given JsonCodec[ApplicationResponse]    = DeriveJsonCodec.gen
  given JsonCodec[CreateApplicationBody]  = DeriveJsonCodec.gen
  given JsonCodec[UpdateApplicationBody]  = DeriveJsonCodec.gen
  given JsonCodec[RoleResponse]           = DeriveJsonCodec.gen
}
