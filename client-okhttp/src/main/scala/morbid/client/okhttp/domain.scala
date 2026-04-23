package morbid.client.okhttp

import java.time.{LocalDateTime, ZonedDateTime}
import com.fasterxml.jackson.annotation.JsonIgnoreProperties

/**
 * Self-contained domain types matching morbid (m) server JSON format.
 * These are Scala 2.12 compatible equivalents of the Scala 3 opaque types in morbid-commons.
 */

// --- Raw domain types (server responses) ---

@JsonIgnoreProperties(ignoreUnknown = true)
case class RawAccount(
  id         : Long,
  created    : LocalDateTime,
  deleted    : Option[LocalDateTime],
  tenant     : Long,
  tenantCode : String,
  active     : Boolean,
  code       : String,
  name       : String
)

@JsonIgnoreProperties(ignoreUnknown = true)
case class RawUserEntry(
  id      : Long,
  created : LocalDateTime,
  deleted : Option[LocalDateTime],
  account : Long,
  kind    : Option[String],
  code    : String,
  active  : Boolean,
  email   : String
)

@JsonIgnoreProperties(ignoreUnknown = true)
case class RawUserDetails(
  id          : Long,
  created     : LocalDateTime,
  deleted     : Option[LocalDateTime] = None,
  tenant      : Long,
  tenantCode  : String,
  account     : Long,
  accountCode : String,
  kind        : Option[String]        = None,
  active      : Boolean,
  code        : String,
  email       : String
)

@JsonIgnoreProperties(ignoreUnknown = true)
case class RawGroup(
  id      : Long,
  created : LocalDateTime,
  deleted : Option[LocalDateTime],
  code    : String,
  name    : String,
  roles   : Seq[RawRole] = Seq.empty
)

@JsonIgnoreProperties(ignoreUnknown = true)
case class RawRole(
  id          : Long,
  created     : LocalDateTime,
  deleted     : Option[LocalDateTime],
  code        : String,
  name        : String,
  permissions : Seq[RawPermission] = Seq.empty
)

@JsonIgnoreProperties(ignoreUnknown = true)
case class RawPermission(
  id      : Long,
  created : LocalDateTime,
  deleted : Option[LocalDateTime],
  code    : String,
  name    : String
)

// --- Token types ---

@JsonIgnoreProperties(ignoreUnknown = true)
case class CompactGroup(
  code  : String,
  roles : Seq[String] = Seq.empty
)

@JsonIgnoreProperties(ignoreUnknown = true)
case class CompactApplication(
  id     : Long,
  code   : String,
  groups : Seq[CompactGroup] = Seq.empty
)

@JsonIgnoreProperties(ignoreUnknown = true)
case class CompactUser(
  details      : RawUserDetails,
  applications : Seq[CompactApplication] = Seq.empty
)

@JsonIgnoreProperties(ignoreUnknown = true)
case class Token(
  created        : ZonedDateTime,
  expires        : Option[ZonedDateTime],
  user           : CompactUser,
  impersonatedBy : Option[RawUserDetails] = None
) {
  def hasRole(code: String, app: String): Boolean =
    (for {
      a <- user.applications.find(_.code == app)
      _ <- a.groups.flatMap(_.roles).find(_ == code)
    } yield true).getOrElse(false)

  def narrowTo(app: String): Option[SingleAppToken] =
    user.applications
      .find(_.code == app)
      .map(found => SingleAppToken(created, expires, SingleAppUser(user.details, found, impersonatedBy)))
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
  def hasRole(code: String): Boolean =
    user.application.groups.flatMap(_.roles).contains(code)
}

// --- Request types ---

case class StoreUserRequest(
  id       : Option[Long]   = None,
  code     : Option[String] = None,
  kind     : Option[String] = None,
  email    : String,
  password : Option[String] = None,
  tenant   : Option[String] = None,
  active   : Boolean,
  update   : Boolean
)

case class StoreAccountRequest(
  id     : Option[Long] = None,
  tenant : Long,
  name   : String,
  code   : String,
  active : Boolean,
  update : Boolean
)

case class StoreGroupRequest(
  id    : Option[Long]   = None,
  code  : Option[String] = None,
  name  : String,
  users : Seq[String]    = Seq.empty,
  roles : Seq[String]    = Seq.empty
)

case class RemoveUserRequest(code: String)
case class RemoveGroupRequest(code: String)
case class RequestPasswordResetLink(email: String)
case class ChangePasswordRequest(email: String, password: String)
case class PasswordResetLink(link: String)
case class SetUserPin(email: String, pin: String)
case class ValidateUserPin(pin: String)
case class ImpersonationRequest(email: String, magic: String)
case class LoginViaEmailLinkRequest(email: String, url: String)
case class LoginViaEmailLinkResponse(link: String)

// --- Verify request (internal) ---
private[okhttp] case class SimpleToken(token: String)
