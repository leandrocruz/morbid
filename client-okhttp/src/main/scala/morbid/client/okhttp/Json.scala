package morbid.client.okhttp

import com.fasterxml.jackson.databind.{DeserializationFeature, ObjectMapper, SerializationFeature}
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.scala.DefaultScalaModule

private[okhttp] object Json {

  val mapper: ObjectMapper = new ObjectMapper()
    .registerModule(DefaultScalaModule)
    .registerModule(new JavaTimeModule)
    .registerModule(new Jdk8Module)
    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
    .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)

  def encode(value: Any): String =
    mapper.writeValueAsString(value)

  def decode[T](json: String)(implicit m: Manifest[T]): T =
    mapper.readValue(json, m.runtimeClass.asInstanceOf[Class[T]])

  def decodeSeq[T](json: String)(implicit m: Manifest[T]): Seq[T] = {
    val javaType = mapper.getTypeFactory.constructCollectionType(classOf[java.util.List[_]], m.runtimeClass)
    import scala.collection.JavaConverters._
    mapper.readValue[java.util.List[T]](json, javaType).asScala.toSeq
  }
}
