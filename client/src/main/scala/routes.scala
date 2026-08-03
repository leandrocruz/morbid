package morbid

import guara.utils.Origin
import morbid.client.MorbidClient
import morbid.domain.token.{RawToken, SingleAppToken, Token}
import morbid.types.ApplicationCode
import morbid.{MorbidError, MorbidRouterOps}
import zio.http.*
import zio.json.EncoderOps
import zio.{Task, ZIO, ZLayer}

trait MorbidRoutes {
  def routes: Routes[Any, Nothing]
}

object MorbidRoutes {
  def layer()(using ApplicationCode, Origin) = ZLayer.fromFunction(OnlyMorbidRoutes.apply)
}

case class OnlyMorbidRoutes(morbid: MorbidClient)(using ApplicationCode, Origin) extends MorbidRoutes with MorbidRouterOps {

  override def tokenFrom(request: Request): Task[Token] = {
    ZIO.foreach(rawTokenFrom(request)) { morbid.tokenFrom }.someOrFail(MorbidError.noToken)
  }

  private def login(request: Request): Task[Response] = {
    for
      response <- morbid.proxy(request)
      res      <- narrowResponse("Login")(response)
    yield res
  }

  private def whoami = ensureAccount { request =>
    val tk = summon[SingleAppToken]
    ZIO.succeed(Response.json(tk.toJson))
  }

  override def routes: Routes[Any, Nothing] = Routes(
    Method.POST / "login"  -> Handler.fromFunctionZIO[Request](login),
    Method.GET  / "whoami" -> Handler.fromFunctionZIO[Request](whoami),
  ).sandbox
}