package morbid

import types.*
import zio.*
import zio.json.*
import zio.test.*
import zio.test.Assertion.*
import io.jsonwebtoken.{Jwts, Jws}

object JwtSpec extends ZIOSpecDefault {
  def spec =
    suite("JwtSpec")(
      test("claims") {
        val sub = "Leandro"
        val key = Jwts.SIG.HS256.key().build
        val jws = Jwts.builder.subject(sub).signWith(key).compact
        val payload = Jwts.parser.verifyWith(key).build.parseSignedClaims(jws).getPayload
        assertTrue(payload.getSubject == sub)
      },
      test("content") {
        val sub = s"""#{"name": "Leandro"}""" /* FIXME: It seems that, if the string starts with {}, the visitor is ignored */
        val key = Jwts.SIG.HS256.key().build
        val jws = Jwts.builder.content(sub).signWith(key).compact
        val payload = Jwts.parser.verifyWith(key).build.parse(jws).accept(Jws.CONTENT).getPayload
        assertTrue(payload == sub.toArray)
      }
    )
}