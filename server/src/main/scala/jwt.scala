package morbid

import zio.*

object tokens {

  import domain.raw.RawUser
  import domain.token.Token
  import morbid.config.MorbidConfig
  import better.files._
  import guara.errors.ReturnResponseError
  import zio.json.*
  import zio.http.Response
  import io.jsonwebtoken.{Jwts, Jws}
  import java.util.Base64
  import javax.crypto.spec.SecretKeySpec
  import java.time.{ZoneId, ZonedDateTime}

  trait TokenGenerator {
    def encode(user: RawUser)   : Task[String]
    def verify(payload: String) : Task[Token]
  }

  object TokenGenerator {
    val layer = ZLayer {

      def readKey(config: MorbidConfig) = ZIO.attempt {
        val bytes   = File(config.jwt.key).byteArray
        val decoded = Base64.getDecoder.decode(bytes)
        new SecretKeySpec(decoded, 0, decoded.length, "HmacSHA512")
      }

      for {
        config  <- ZIO.service[MorbidConfig]
        key     <- readKey(config)
        zone    <- ZIO.attempt(config.clock.timezone).map(ZoneId.of)
      } yield JwtTokenGenerator(key, zone)
    }
  }

  case class JwtTokenGenerator (key: SecretKeySpec, zone: ZoneId) extends TokenGenerator {

    private val parser = Jwts.parser().verifyWith(key).build()

    /**
     * https://github.com/jwtk/jjwt#jwt-create
     */
    override def encode(user: RawUser): Task[String] = {

      def encodeAsJson(now: ZonedDateTime) = ZIO.attempt {
        Token(
          created = now,
          expires = Some(now.plusDays(1)), //TODO: define the expiration policy based on the tenant/account/etc
          user    = user
        ).toJson
      }

      def build(content: String) = {
        ZIO.attempt {
          Jwts
            .builder()
            .header()
              .contentType("application/json")
              .add("version", "v1")
              .add("issuer", "morbid")
            .and()
            .content(content)
            .signWith(key)
            .compact()
        }
      }

      for {
        now     <- Clock.localDateTime
        content <- encodeAsJson(now.atZone(zone))
        result  <- build(content)
      } yield result

    }

    override def verify(payload: String): Task[Token] = {

      def asToken(str: String): Task[Token] = {
        ZIO.fromEither(str.fromJson[Token]).mapError(new Exception(_))
      }

      def isExpired(token: Token, now: ZonedDateTime): Boolean = {
        token.expires match {
          case Some(exp) => now.isAfter(exp)
          case _        => false
        }
      }

      for {
        generic <- ZIO.attempt(parser.parse(payload))
        str     <- ZIO.attempt(generic.accept(Jws.CONTENT).getPayload)
        token   <- asToken(new String(str))
        now     <- Clock.localDateTime
        expired =  isExpired(token, now.atZone(zone))
        _       <- ZIO.when(expired) { ZIO.fail(ReturnResponseError(Response.forbidden("Token is expired"))) }
      } yield token
    }
  }
}

