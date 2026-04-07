package morbid.config

import zio.*

import morbid.legacy.LegacyClientConfig

import zio.config.*
import zio.config.magnolia.*
import zio.config.typesafe.*
import Config.*

case class JwtConfig(key: String, fake: Boolean)
case class IdentityConfig(key: String, database: String, provisionSAMLUsers: Boolean)
case class ClockConfig(timezone: String)
case class MagicConfig(password: String)
case class PinConfig(prefix: String, default: String)
case class ServiceConfig(token: String)
case class MorbidConfig(identities: IdentityConfig, jwt: JwtConfig, clock: ClockConfig, magic: MagicConfig, pin: PinConfig, legacy: LegacyClientConfig, printQueries: Boolean, service: ServiceConfig)

object MorbidConfig {

  val layer = ZLayer {
    TypesafeConfigProvider.fromResourcePath(enableCommaSeparatedValueAsList = true).load(deriveConfig[MorbidConfig])
  }

  val legacy = ZLayer {
    for {
      cfg <- ZIO.service[MorbidConfig]
    } yield cfg.legacy
  }
}