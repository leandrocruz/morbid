package morbid.admin.api

import guara.GuaraApp
import guara.background.BackgroundServices
import morbid.client.{MorbidClient, MorbidClientConfig}
import zio.*
import zio.http.Client
import zio.logging.backend.SLF4J

object AdminApiServer extends GuaraApp {

  override val bootstrap = Runtime.removeDefaultLoggers >>> SLF4J.slf4j

  private val morbidClientConfig = ZLayer {
    for config <- ZIO.service[AppConfig]
    yield MorbidClientConfig(url = config.morbid.url, mode = "remote")
  }

  override val run = startGuara.provide(
    BackgroundServices.none,
    AppConfig.layer,
    Client.default,
    Scope.default,
    morbidClientConfig,
    MorbidClient.layer,
    MorbidGateway.layer,
    AdminAuth.layer,
    AdminRouter.layer,
  )
}
