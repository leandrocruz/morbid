package morbid

object MorbidError {

  val Forbidden           = 1
  val Unauthorized        = 2
  val BadRequest          = 3
  val TokenError          = 98
  val BadMagic            = 99

  val TenantError    = 100
  val TenantNotFound = 101

  val ApplicationError    = 200
  val ApplicationNotFound = 201

  val AccountError          = 300
  val AccountNotFound       = 301
  val LegacyAccountNotFound = 302
  val IdentifierTaken       = 303

  val UsersError         = 400
  val UserNotFound       = 401
  val LegacyUserNotFound = 402
  val EmailTaken         = 403
  val UserAlreadyExists  = 404

  val PlanError    = 500
  val PlanNotFound = 501

  val GroupError    = 600
  val GroupNotFound = 601

  val FirebaseError = 900
}