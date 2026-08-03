package morbid

import guara.errors.{GuaraError, ReturnResponseError}
import guara.uef
import guara.utils.{Origin, ensureResponse, parse}
import morbid.MorbidError
import morbid.domain.token.{RawToken, SingleAppToken, Token}
import morbid.secure.{AppRoute, appRoute}
import morbid.types.ApplicationCode
import zio.http.*
import zio.json.EncoderOps
import zio.{Cause, Task, ZIO}

type AutenticatedRequest = SingleAppToken ?=> Request => Task[Response]

trait MorbidRouterOps {

//  def appCode: ApplicationCode
//  def origin : Origin

  def tokenFrom(request: Request): Task[Token]

  def protect(r: AppRoute)(app: String, request: Request)(using Origin): Task[Response] = {
    ensureResponse(appRoute(ApplicationCode.of(app), tokenFrom)(r)(request)).toTask
  }

  def rawTokenFrom(request: Request): Option[RawToken] = {
    request
      .headers
      .get(morbid.MorbidHeaders.Token)
      .orElse(request.cookie(morbid.MorbidCookies.Token).map(_.content))
      .map(RawToken.of)
  }

  def narrow(token: Token)(using application: ApplicationCode): Task[SingleAppToken] = {
    token.narrowTo(application) match
      case Some(value) => ZIO.succeed(value)
      case None        => MorbidError.failNotAuthorized(s"Can't find application '$application' on user credentials")
  }

  def narrowResponse(op: String)(response: Response)(using ApplicationCode) = {
    val isUEF = response.headers.exists(uef.isUEFHeader)
    for
      _       <- ZIO.logInfo(s"$op (error ? ${isUEF})")
      _       <- ZIO.when(isUEF) { ZIO.fail(ReturnResponseError(response)) }
      token   <- response.body.parse[Token]().mapError(GuaraError.of(s"Error parsing token"))
      headers =  Headers(response.headers.filterNot(_.headerType == Header.ContentLength))
      result  <- narrow(token)
    yield Response.json(result.toJson).addHeaders(headers)
  }

  def ensureAccount(fn: AutenticatedRequest)(request: Request)(using ApplicationCode, Origin): Task[Response] = {

    def execute(using SingleAppToken)     = fn(request).tapError(logError).tapDefect(logCause)
    def logError(cause: Throwable)        = ZIO.logErrorCause(s"Error: ${cause.getMessage}", Cause.fail(cause))
    def logCause(cause: Cause[Throwable]) = ZIO.logErrorCause(s"Defect: ${cause.squash.getMessage}", cause)

    def appTokenFrom(request: Request): Task[SingleAppToken] = {
      for
        tk     <- tokenFrom(request)
        result <- narrow(tk)
      yield result
    }

    ensureResponse {
      for
        token  <- appTokenFrom(request)
        result <- execute(using token) //@@ presto.track.account(token)
      yield result
    }.toTask
  }

}