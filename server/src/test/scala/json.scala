package morbid

import guara.utils.{safeCode, safeName}
import types.*
import zio.*
import zio.json.*
import zio.test.*
import zio.test.Assertion.*

object JsonSpec extends ZIOSpecDefault {

  case class CodeAndName(code: RoleCode, name: RoleName)

  given JsonEncoder[CodeAndName] = DeriveJsonEncoder.gen[CodeAndName]
  given JsonDecoder[CodeAndName] = DeriveJsonDecoder.gen[CodeAndName]

  def spec =
    suite("JsonSpec") (
      test("valid name decode")      { assert(safeName(10).decodeJson("\"NAME\""))      { isRight (equalTo("NAME")) } },
      test("whitespace name decode") { assert(safeName(10).decodeJson("\"N    A ME\"")) { isRight (equalTo("N A ME")) } },
      test("big name decode")        { assert(safeName(3) .decodeJson("\"NAME\""))      { isLeft  (equalTo("('NAME' must have at most 3 chars)"))  } },
      test("bad name decode")        { assert(safeName(10).decodeJson("\"/NAME\""))     { isLeft  (equalTo("('/NAME' has invalid chars)")) } },
      test("valid code decode")      { assert(safeCode(10).decodeJson("\"code\""))      { isRight (equalTo("code")) } },
      test("valid code decode2")     { assert(safeCode(10).decodeJson("\"co_e\""))      { isRight (equalTo("co_e")) } },
      test("whitespace code decode") { assert(safeCode(10).decodeJson("\"c ode\""))     { isLeft  (equalTo("('c ode' has invalid chars)")) } },

      test("encode/decode") {
        val obj = CodeAndName(RoleCode.of("code"), RoleName.of("My Name is Tanaka"))
        assert(obj.toJson.fromJson[CodeAndName]) { isRight(equalTo(obj)) }
      }
    )
}