package morbid

object track {

  import morbid.types.*
  import morbid.domain.token.SingleAppToken
  import zio.ZIOAspect

  def account(token: SingleAppToken) = zio.logging.loggerName("account") @@ ZIOAspect.annotated("account", AccountId.value(token.user.details.account).toString)
}

object secure {

  import domain.raw.RawUserDetails
  import types.ApplicationCode
  import domain.token.{SingleAppToken, Token}
  import roles.Role
  import guara.http.Origin
  import guara.http.errors.*
  import zio.http.*
  import zio.*

  type AppRoute       = (SingleAppToken, ApplicationCode) ?=> Request => Task[Response]
  type TokenValidator = SingleAppToken => Either[String, Unit]

  val AllowAll: TokenValidator = _ => Right(())

  def role(role: Role, allow: TokenValidator = AllowAll)(fn: Request => Task[Response])(request: Request)(using token: SingleAppToken): Task[Response] = {

    def forbidden(message: String) = ZIO.fail(ReturnResponseError(Response.forbidden(message)))

    def test(token: SingleAppToken): Task[Unit] = {
      if (role.isSatisfiedBy(token)) ZIO.unit
      else                           forbidden(s"Required role '$role' is missing from user token (application: ${token.user.application.code})")
    }

    def execute = {
      def log(maybe: Option[RawUserDetails]) = {
        maybe match
          case Some(imp) => ZIO.logWarning(s"Executing impersonated request at '${request.url.path.encode}' by '${imp.id}/${imp.email}' on behalf of '${token.user.details.id}/${token.user.details.email}' on app '${token.user.application.code}'")
          case None      => ZIO.logInfo   (s"Executing request at '${request.url.path.encode}' by '${token.user.details.id}/${token.user.details.email}' on app '${token.user.application.code}'")
      }

      for
        _      <- log(token.user.impersonatedBy)
        result <- fn(request)
      yield result
    }

    for
      _      <- allow(token) match {
               case Left(err) => forbidden(err)
               case Right(_)  => test(token)
             }
      result <- execute @@ morbid.track.account(token)
    yield result
  }

  def appRoute(application: ApplicationCode, tokenFrom: Request => Task[Token])(route: AppRoute)(request: Request)(using Origin): Task[Response] = {

    def execute(token: SingleAppToken) = {
      given SingleAppToken  = token
      given ApplicationCode = application
      route(request)
    }

    for
      _     <- ZIO.logInfo(s"Executing app route for app '${application}'")
      token <- tokenFrom(request)
      _     <- ZIO.logInfo(s"Token extracted ${token.user.details.email}")
      sat   <- ZIO.fromOption(token.narrowTo(application)).mapError(_ => ReturnResponseError(Response.forbidden(s"User has no access to application '$application'")))
      _     <- ZIO.logInfo(s"Token narrowed. Executing")
      res   <- execute(sat)
    yield res
  }
}
