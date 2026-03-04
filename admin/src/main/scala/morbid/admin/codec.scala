package morbid.admin

import medulla.fetch.{RequestEncoder, ResponseDecoder}
import zio.json.{JsonEncoder, JsonDecoder}
import scala.util.{Try, Success, Failure}

object codec {

  given zioJsonRequestEncoder[T: JsonEncoder]: RequestEncoder[T] with
    def encode(i: T): Try[String] = Success(JsonEncoder[T].encodeJson(i, None).toString)

  given zioJsonResponseDecoder[T: JsonDecoder]: ResponseDecoder[T] with
    def decode(text: String): Try[T] =
      JsonDecoder[T].decodeJson(text) match
        case Right(v) => Success(v)
        case Left(e)  => Failure(new RuntimeException(s"JSON decode error: $e"))
}
