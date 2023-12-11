package morbid

import zio.*

object tokens {

  import morbid.config.MorbidConfig
  import domain.mini.MiniUser
  import better.files._
  import io.jsonwebtoken.Jwts
  import zio.json.*
  import java.util.Base64
  import javax.crypto.spec.SecretKeySpec
  import java.time.{ZoneId, ZonedDateTime}

  trait TokenGenerator {
    def encode(user: MiniUser): Task[String]
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

  private case class Token(
    created: ZonedDateTime,
    expires: Option[ZonedDateTime],
    user   : MiniUser
  )

  private given JsonEncoder[Token] = DeriveJsonEncoder.gen[Token]

  case class JwtTokenGenerator (key: SecretKeySpec, zone: ZoneId) extends TokenGenerator {

    /**
     * https://github.com/jwtk/jjwt#jwt-create
     */
    override def encode(user: MiniUser): Task[String] = {

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
  }
}

