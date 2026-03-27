package morbid.logback

import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.sift.AbstractDiscriminator
import scala.jdk.CollectionConverters.*

class AccountDiscriminator extends AbstractDiscriminator[ILoggingEvent] {

  override def getDiscriminatingValue(e: ILoggingEvent): String = {
    e.getKeyValuePairs.asScala.find(_.key == "account").map(_.value.toString).getOrElse("no-account")
  }

  override def getKey: String = "account"
}
