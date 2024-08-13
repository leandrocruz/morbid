package morbid

import router.MorbidRouter
import guara.GuaraApp
import guara.processor.Processor
import morbid.accounts.AccountManager
import morbid.billing.Billing
import morbid.config.MorbidConfig
import morbid.gip.Identities
import morbid.legacy.LegacyMorbid
import morbid.pins.PinManager
import morbid.tokens.TokenGenerator
import morbid.repo.Repo
import morbid.passwords.PasswordGenerator
import zio.*
import zio.http.Client
import zio.logging.LogFormat
import zio.logging.backend.SLF4J

object MorbidServer extends GuaraApp {

  //FIXME: DO NOT ENABLE THIS. It breaks stack trace logging
  //override val bootstrap = Runtime.removeDefaultLoggers >>> SLF4J.slf4j(LogFormat.colored)

  override val run = startGuara.provide(
    MorbidConfig.layer,
    MorbidConfig.legacy,
    Client.default,
    Scope.default,
    LegacyMorbid.layer,
    AccountManager.layer,
    Billing.layer,
    Identities.layer,
    MorbidRouter.layer,
    PasswordGenerator.layer,
    PinManager.layer,
    Processor.drop,
    Repo.datasource,
    Repo.layer,
    TokenGenerator.layer
  )
}
