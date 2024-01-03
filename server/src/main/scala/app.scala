package morbid

import router.MorbidRouter
import guara.GuaraApp
import guara.processor.Processor
import morbid.accounts.AccountManager
import morbid.config.MorbidConfig
import morbid.gip.Identities
import morbid.tokens.TokenGenerator
import morbid.repo.Repo
import zio.*
import zio.logging.LogFormat
import zio.logging.backend.SLF4J

object MorbidServer extends GuaraApp {

  override val bootstrap = Runtime.removeDefaultLoggers >>> SLF4J.slf4j(LogFormat.colored)

  override val run = startGuara.provide(
    MorbidConfig.layer,
    MorbidRouter.layer,
    Processor.drop,
    Identities.layer,
    AccountManager.layer,
    Repo.layer,
    TokenGenerator.layer
  )
}