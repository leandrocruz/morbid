package morbid.admin

object codec {

  import medulla.fetch.{RequestEncoder, ResponseDecoder}
  import zio.json.{JsonDecoder, JsonEncoder}
  import scala.util.{Failure, Success, Try}

  given zioJsonRequestEncoder[T: JsonEncoder]: RequestEncoder[T] with
    def encode(i: T): Try[String] = Success(JsonEncoder[T].encodeJson(i, None).toString)

  given zioJsonResponseDecoder[T: JsonDecoder]: ResponseDecoder[T] with
    def decode(text: String): Try[T] =
      JsonDecoder[T].decodeJson(text) match
        case Right(v) => Success(v)
        case Left(e)  => Failure(new RuntimeException(s"JSON decode error: $e"))
}

object converters {

  import morbid.types.ApplicationCode
  import medulla.ui.inputs.SafeConverter
  import scala.util.Try

  given SafeConverter[ApplicationCode] = new SafeConverter[ApplicationCode] {
    override def fromText(str: String)      = Try(ApplicationCode.of(str))
    override def asText(t: ApplicationCode) = Try(ApplicationCode.value(t))
  }
}
