package morbid

object track {

  import morbid.types.*
  import morbid.domain.token.SingleAppToken
  import zio.ZIOAspect

  def account(token: SingleAppToken) = zio.logging.loggerName("account") @@ ZIOAspect.annotated("account", AccountId.value(token.user.details.account).toString)
}