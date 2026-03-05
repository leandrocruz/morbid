package morbid.converters

import medulla.ui.inputs.SafeConverter
import morbid.types.*

import scala.util.{Try, Success}

given SafeConverter[ApplicationName] = new SafeConverter[ApplicationName] {
  override def fromText(str: String)      = Try(ApplicationName.of(str))
  override def asText(t: ApplicationName) = Try(ApplicationName.value(t))
}