package morbid

object MorbidError {

  import guara.errors.GuaraError
  import zio.http.Status

  def noToken                                              = GuaraError.of(MorbidErrorCodes.Forbidden, Status.Forbidden, s"Missing authentication token")
  def generic          (message: String)(cause: Throwable) = GuaraError.of(message)(cause)
  def forbidden        (cause: Throwable)                  = GuaraError.of(MorbidErrorCodes.Forbidden, Status.Forbidden, s"Error verifying token")(cause)
  def failNotAuthorized(message: String)                   = GuaraError.fail(MorbidErrorCodes.Unauthorized, Status.Unauthorized, message)
}