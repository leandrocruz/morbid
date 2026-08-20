package morbid

object errors {

  import morbid.MorbidError.*
  import guara.errors.GuaraError.{fail, of}
  import morbid.types.*
  import zio.http.Status

  case class EmailTakenException(email: Email, cause: Throwable = null) extends Exception(s"Email '${Email.value(email)}' already exists", cause)
  case class IdentifierTakenException(identifier: AccountIdentifier, cause: Throwable = null) extends Exception(s"Identifier '${AccountIdentifier.value(identifier)}' already exists", cause)

  def badRequest(message: String)(cause: Throwable) = of  (code = BadRequest     , status = Status.BadRequest   , message = message + ": " + cause.getMessage)(cause)
  def badMagic                                      = fail(code = BadMagic       , status = Status.Unauthorized , message = "bad magic"                      )
  def emailTaken     (email: Email)                 = fail(code = EmailTaken     , status = Status.Conflict     , message = s"Email '$email' already taken"  )
  def identifierTaken(id: AccountIdentifier)        = fail(code = IdentifierTaken, status = Status.Conflict     , message = s"Identifier '$id' already taken")
  def userNotFound   (message: String)              = fail(code = UserNotFound   , status = Status.NotFound     , message = message)
  def notAuthorized  (message: String)              = fail(code = Unauthorized   , status = Status.Unauthorized , message = message)
}