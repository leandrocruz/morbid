package morbid

import router.MorbidRouter
import guara.GuaraApp
import guara.processor.Processor
import morbid.accounts.AccountManager
import morbid.applications.Applications
import morbid.billing.Billing
import morbid.config.MorbidConfig
import morbid.gip.Identities
import morbid.groups.GroupManager
import morbid.roles.RoleManager
import morbid.pins.PinManager
import morbid.tokens.TokenGenerator
import morbid.repo.Repo
import morbid.passwords.PasswordGenerator
import zio.*
import zio.logging.LogFormat
import zio.logging.backend.SLF4J

object MorbidServer extends GuaraApp {

  //FIXME: DO NOT ENABLE THIS. It breaks stack trace logging
  //override val bootstrap = Runtime.removeDefaultLoggers >>> SLF4J.slf4j(LogFormat.colored)

  override val run = startGuara.provide(
    AccountManager.layer,
    Applications.layer,
    Billing.layer,
    GroupManager.layer,
    Identities.layer,
    MorbidConfig.layer,
    MorbidRouter.layer,
    PasswordGenerator.layer,
    PinManager.layer,
    Processor.drop,
    Repo.layer,
    RoleManager.layer,
    TokenGenerator.layer,
  )
}
