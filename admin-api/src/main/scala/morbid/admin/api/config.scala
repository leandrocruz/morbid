package morbid.admin.api

import zio.*
import zio.config.magnolia.*
import zio.config.typesafe.*

case class MorbidCfg (
  url         : String,
  application : String,
)

case class CookieCfg (
  name   : String,
  secure : Boolean,
  domain : Option[String],
)

case class CorsCfg (
  origins : List[String],
)

case class AppConfig (
  morbid : MorbidCfg,
  cookie : CookieCfg,
  cors   : CorsCfg,
)

object AppConfig {
  val layer = ZLayer {
    TypesafeConfigProvider.fromResourcePath(enableCommaSeparatedValueAsList = true).load(deriveConfig[AppConfig])
  }
}
