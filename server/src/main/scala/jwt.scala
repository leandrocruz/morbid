package morbid

import zio.*

object tokens {

  import types.*
  import domain.raw.*
  import domain.token.{Token, CompactUser, CompactApplication, CompactGroup}
  import morbid.config.MorbidConfig
  import better.files._
  import guara.errors.*
  import zio.json.*
  import zio.http.Response
  import io.jsonwebtoken.{Jwts, Jws}
  import java.util.Base64
  import javax.crypto.spec.SecretKeySpec
  import java.time.{ZoneId, ZonedDateTime, LocalDateTime}
  import io.scalaland.chimney.dsl.*

  trait TokenGenerator {
    def verify(payload: String)              : Task[Token]
    def asToken(user: RawUser, days: Int = 1): Task[Token]
    def encode(token: Token)                 : Task[String]
  }

  object TokenGenerator {

    val fake: ULayer[TokenGenerator] = ZLayer.succeed(FakeTokens())

    val layer = ZLayer {

      def build(config: MorbidConfig, zone: ZoneId) = {

        def readKey(config: MorbidConfig) = ZIO.attempt {
          val bytes   = File(config.jwt.key).byteArray
          val decoded = Base64.getDecoder.decode(bytes)
          new SecretKeySpec(decoded, 0, decoded.length, "HmacSHA512")
        }

        for {
          _   <- ZIO.logInfo(s"Loading JWT key from '${config.jwt.key}'")
          key <- readKey(config)
        } yield JwtTokenGenerator(key, zone)
      }

      for {
        config  <- ZIO.service[MorbidConfig]
        zone    <- ZIO.attempt(config.clock.timezone).map(ZoneId.of)
        impl    <- if(config.jwt.fake) ZIO.succeed(FakeTokenGenerator(zone)) else build(config, zone)
      } yield impl
    }
  }

  private case class FakeTokens() extends TokenGenerator {

    val deflt = Token(
      created = ZonedDateTime.now(),
      expires = Some(ZonedDateTime.now().plusDays(1)),
      user    = CompactUser(
        details = RawUserDetails(
          id          = UserId.of(1),
          created     = LocalDateTime.now(),
          deleted     = None,
          tenant      = TenantId.of(1),
          tenantCode  = TenantCode.of("DEFAULT"),
          account     = AccountId.of(1),
          accountCode = AccountCode.of("fake"),
          kind        = None,
          active      = true,
          code        = UserCode.of("fake"),
          email       = Email.of("user@fake.com")
        ),
        applications = Seq(
          CompactApplication(id = ApplicationId.of(1), code = ApplicationCode.of("console"), groups = Seq(CompactGroup(code = GroupCode.of("g1"), roles = Seq(RoleCode.of("adm")))))
        )
      )
    )

    override def verify(payload: String)           = ZIO.succeed(deflt)
    override def asToken(user: RawUser, days: Int) = ZIO.succeed(deflt)
    override def encode(token: Token)              = ZIO.succeed("FAKE")
  }

  private case class FakeTokenGenerator(zone: ZoneId) extends TokenGenerator {
    override def encode(token: Token)   : Task[String] = ZIO.succeed("TODO: encode token")

    override def asToken(user: RawUser, days: Int) : Task[Token]  = {
      for {
        now <- Clock.localDateTime
        at = now.atZone(zone)
      } yield Token(
        created = at,
        expires = Some(at.plusDays(days)), //TODO: define the expiration policy based on the tenant/account/etc
        user = user.transformInto[CompactUser]
      )
    }

    override def verify(payload: String) : Task[Token]  = {

      val roles = Seq(
        RawRole(
          id          = RoleId.of(1),
          created     = LocalDateTime.now,
          deleted     = None,
          code        = RoleCode.of("adm"),
          name        = RoleName.of("Global Admin"),
          permissions = Seq.empty
        )
      )

      val groups = Seq(
        RawGroup(
          id      = GroupId.of(1),
          created = LocalDateTime.now,
          deleted = None,
          code    = GroupCode.of("g1"),
          name    = GroupName.of("G1"),
          roles   = roles
        )
      )

      val apps = Seq(
        RawApplication(
          details = RawApplicationDetails(
            id      = ApplicationId.of(1),
            created = LocalDateTime.now(),
            deleted = None,
            active  = true,
            code    = ApplicationCode.of("console"),
            name    = ApplicationName.of("Console")
          ),
          groups  = groups
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
        ).transformInto[CompactUser]
      )
    }
  }

  private case class JwtTokenGenerator (key: SecretKeySpec, zone: ZoneId) extends TokenGenerator {

    private val parser = Jwts.parser().verifyWith(key).build()

    override def asToken(user: RawUser, days: Int): Task[Token] = {
      for {
        now <- Clock.localDateTime
        at  =  now.atZone(zone)
      } yield Token(
        created = at,
        expires = Some(at.plusDays(days)), //TODO: define the expiration policy based on the tenant/account/etc
        user    = user.transformInto[CompactUser]
      )
    }

    /**
     * https://github.com/jwtk/jjwt#jwt-create
     */
    override def encode(token: Token): Task[String] = {

      def build(content: String) = ZIO.attempt {
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

      for {
        encoded <- ZIO.attempt(token.toJson)
        result  <- build(encoded)
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
        _       <- ZIO.when(expired) { ZIO.fail(Exception(s"Token is expired since '${token.expires.getOrElse("???")}'")) }
      } yield token
    }
  }
}

