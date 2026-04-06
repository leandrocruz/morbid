package morbid.routes

import guara.errors.ReturnResponseError
import morbid.client.MorbidClient
import morbid.types.ApplicationCode
import zio.*
import zio.http.*
import guara.utils.parse
import morbid.domain.token.{SingleAppToken, Token}
import zio.json.EncoderOps


trait MorbidRoutes {
  def routes: Routes[Any, Nothing]
}

object MorbidRoutes {
  val layer = ZLayer.fromFunction(OnlyMorbidRoutes.apply _)
}

case class OnlyMorbidRoutes(morbid: MorbidClient, app: ApplicationCode) extends MorbidRoutes {

  private def narrow(token: Token)(using app: ApplicationCode): Task[SingleAppToken] = {

    def unauthorized(token: Token) = {
      val msg = s"Can't find application '$app' on user credentials"
      ReturnResponseError {
        Response
          .json(token.toJson)
          .status(Status.Unauthorized)
          .addHeader(Header.Custom("explanation", msg))
      }
    }

    token.narrowTo(app) match
      case Some(value) => ZIO.succeed(value)
      case None        => ZIO.fail(unauthorized(token))
  }

  override def routes = {

    def login(request: Request): Task[Response] = {
      for
        response <- morbid.proxy(request)
        token    <- response.body.parse[Token]()
        sap      <- narrow(token)(using app)
      yield Response.json(sap.toJson)
    }

    Routes(
      Method.POST / "login" -> Handler.fromFunctionZIO[Request](login),
    ).sandbox
  }
}
