package morbid

import zio.*

object tokens {

  import types.*
  import domain.raw.*
  import domain.token.Token
  import morbid.config.MorbidConfig
  import better.files._
  import guara.errors.ReturnResponseError
  import zio.json.*
  import zio.http.Response
  import io.jsonwebtoken.{Jwts, Jws}
  import java.util.Base64
  import javax.crypto.spec.SecretKeySpec
  import java.time.{ZoneId, ZonedDateTime, LocalDateTime}

  trait TokenGenerator {
    def verify(payload: String) : Task[Token]
    def asToken(user: RawUser)  : Task[Token]
    def encode(token: Token)    : Task[String]
  }

  object TokenGenerator {
    val layer = ZLayer {

      def build(config: MorbidConfig, zone: ZoneId) = {

        def readKey(config: MorbidConfig) = ZIO.attempt {
          val bytes   = File(config.jwt.key).byteArray
          val decoded = Base64.getDecoder.decode(bytes)
          new SecretKeySpec(decoded, 0, decoded.length, "HmacSHA512")
        }

        for {
          _    <- ZIO.logInfo(s"Loading JWT key from '${config.jwt.key}'")
          key  <- readKey(config)
        } yield JwtTokenGenerator(key, zone)
      }

      for {
        config  <- ZIO.service[MorbidConfig]
        zone    <- ZIO.attempt(config.clock.timezone).map(ZoneId.of)
        impl    <- if(config.jwt.fake) ZIO.succeed(FakeTokenGenerator(zone)) else build(config, zone)
      } yield impl
    }
  }

  private case class FakeTokenGenerator(zone: ZoneId) extends TokenGenerator {
    override def encode(token: Token)   : Task[String] = ZIO.succeed("TODO: encode token")

    override def asToken(user: RawUser) : Task[Token]  = {
      for {
        now <- Clock.localDateTime
        at = now.atZone(zone)
      } yield Token(
        created = at,
        expires = Some(at.plusDays(1)), //TODO: define the expiration policy based on the tenant/account/etc
        user = user
      )
    }

    override def verify(payload: String) : Task[Token]  = {

      val groups = Seq(
        RawGroup(
          id      = GroupId.of(1),
          created = LocalDateTime.now,
          deleted = None,
          code    = GroupCode.of("g1"),
          name    = GroupName.of("G1")
        )
      )

      val roles = Seq(
        RawRole(
          id          = RoleId.of(1),
          created     = LocalDateTime.now,
          deleted     = None,
          code        = RoleCode.of("user_adm"),
          name        = RoleName.of("User Admin"),
          permissions = Seq.empty
        ),
        RawRole(
          id          = RoleId.of(2),
          created     = LocalDateTime.now,
          deleted     = None,
          code        = RoleCode.of("group_adm"),
          name        = RoleName.of("Group Admin"),
          permissions = Seq.empty
        )

      )

      val apps = Seq(
        RawApplication(
          details = RawApplicationDetails(
            id      = ApplicationId.of(1),
            created = LocalDateTime.now(),
            deleted = None,
            active  = true,
            code    = ApplicationCode.of("morbid"),
            name    = ApplicationName.of("Morbid")
          ),
          groups = groups,
          roles  = roles
        )
      )

      for {
        now  <- Clock.localDateTime

      } yield Token(
        created = now.atZone(zone),
        expires = None,
        user    = RawUser(
          applications = apps,
          details      = RawUserDetails(
            id          = UserId.of(1),
            created     = now,
            deleted     = None,
            tenant      = TenantId.of(1),
            tenantCode  = TenantCode.of("DEFAULT"),
            account     = AccountId.of(1),
            accountCode = AccountCode.of("a1"),
            kind        = None,
            active      = true,
            code        = UserCode.of("usr1"),
            email       = Email.of("usr1@email.com")
          )
        )
      )
    }
  }

  private case class JwtTokenGenerator (key: SecretKeySpec, zone: ZoneId) extends TokenGenerator {

    private val parser = Jwts.parser().verifyWith(key).build()

    override def asToken(user: RawUser): Task[Token] = {
      for {
        now <- Clock.localDateTime
        at  =  now.atZone(zone)
      } yield Token(
        created = at,
        expires = Some(at.plusDays(1)), //TODO: define the expiration policy based on the tenant/account/etc
        user    = user
      )
    }

    /**
     * https://github.com/jwtk/jjwt#jwt-create
     */
    override def encode(token: Token): Task[String] = {
      ZIO.attempt {
        Jwts
          .builder()
          .header()
            .contentType("application/json")
            .add("version", "v1")
            .add("issuer", "morbid")
          .and()
          .content(token.toJson)
          .signWith(key)
          .compact()
      }
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

