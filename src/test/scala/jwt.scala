package morbid

import types.*
import zio.*
import zio.json.*
import zio.test.*
import zio.test.Assertion.*
import io.jsonwebtoken.{Jwts, Jws}
import pdi.jwt.{JwtAlgorithm, JwtClaim, JwtZIOJson}


object JwtSpec extends ZIOSpecDefault {
  def spec =
    suite("JwtSpec")(
      test("claims") {
        val sub = "Leandro"
        val key = Jwts.SIG.HS256.key().build
        val encoded = Jwts.builder.subject(sub).signWith(key).compact
        val decoded = Jwts.parser.verifyWith(key).build.parseSignedClaims(encoded).getPayload
        assertTrue(decoded.getSubject == sub)
      },
      test("raw json") {
        val sub = s"""{"name": "Leandro"}"""
        val key = Jwts.SIG.HS256.key().build
        val encoded = Jwts
          .builder()
          .header()
          .contentType("application/json")
          .add("version", "v1")
          .add("issuer", "morbid")
          .and()
          .content(sub)
          .signWith(key)
          .compact()
        val decoded = Jwts.parser.verifyWith(key).build.parse(encoded).accept(Jws.CONTENT).getPayload
        assertTrue(decoded == sub.toArray)
      }
    )
}