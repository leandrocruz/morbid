package morbid

import types.*
import domain.raw.*
import domain.token.*
import zio.json.*
import zio.test.*
import zio.test.Assertion.*

import java.time.{LocalDateTime, ZonedDateTime}

object PlansSpec extends ZIOSpecDefault {

  private val now = ZonedDateTime.parse("2026-05-21T10:00:00Z")

  private def feature(code: String, value: Option[Long] = None): CompactFeature =
    CompactFeature(FeatureCode.of(code), value)

  private def plan(code: String, features: CompactFeature*): CompactPlan =
    CompactPlan(PlanCode.of(code), features.toSeq)

  private def buildToken(plans: Seq[CompactPlan]): Token = {
    val details = RawUserDetails(
      id          = UserId.of(1),
      created     = LocalDateTime.now,
      tenant      = TenantId.of(1),
      tenantCode  = TenantCode.of("DEFAULT"),
      account     = AccountId.of(1),
      accountCode = AccountCode.of("a1"),
      active      = true,
      code        = UserCode.of("u1"),
      email       = Email.of("u1@x.com"),
    )
    val app = CompactApplication(
      id     = ApplicationId.of(2),
      code   = ApplicationCode.of("presto"),
      plans  = plans,
    )
    Token(created = now, expires = None, user = CompactUser(details, Seq(app)))
  }

  def spec =
    suite("PlansSpec")(
      test("CompactFeature round-trips through JSON (with value)") {
        val f       = feature("tfa", Some(10L))
        val decoded = f.toJson.fromJson[CompactFeature]
        assert(decoded)(isRight(equalTo(f)))
      },
      test("CompactFeature round-trips through JSON (no value)") {
        val f       = feature("tfa")
        val decoded = f.toJson.fromJson[CompactFeature]
        assert(decoded)(isRight(equalTo(f)))
      },
      test("CompactPlan round-trips through JSON") {
        val p       = plan("legacy", feature("tfa"), feature("credentials"))
        val decoded = p.toJson.fromJson[CompactPlan]
        assert(decoded)(isRight(equalTo(p)))
      },
      test("CompactApplication carries plans through JSON") {
        val app = CompactApplication(
          id    = ApplicationId.of(2),
          code  = ApplicationCode.of("presto"),
          plans = Seq(plan("2fa_freemium", feature("tfa", Some(5L)))),
        )
        val decoded = app.toJson.fromJson[CompactApplication]
        assert(decoded)(isRight(equalTo(app)))
      },
      test("hasFeature true for granted, false for missing") {
        given ApplicationCode = ApplicationCode.of("presto")
        val token = buildToken(Seq(plan("legacy", feature("tfa"), feature("credentials"))))
        assertTrue(token.hasFeature(FeatureCode.of("tfa")), !token.hasFeature(FeatureCode.of("sites")))
      },
      test("featureValue sums across plans") {
        // P1: F1 (value 9), F2 (no value).  P2: F1 (value 1), F3 (no value).
        // A1 has P1+P2 => F1 = Some(10), F2 = None (presence only), F3 = None (presence only)
        given ApplicationCode = ApplicationCode.of("presto")
        val token = buildToken(Seq(
          plan("p1", feature("f1", Some(9L)), feature("f2")),
          plan("p2", feature("f1", Some(1L)), feature("f3")),
        ))
        assertTrue(
          token.featureValue(FeatureCode.of("f1")) == Some(10L),
          token.featureValue(FeatureCode.of("f2")) == None,
          token.featureValue(FeatureCode.of("f3")) == None,
          token.hasFeature(FeatureCode.of("f2")),
          token.hasFeature(FeatureCode.of("f3")),
        )
      },
      test("featureValue ignores presence-only grants when a value is defined elsewhere") {
        // P1: F2 (no value).  P2: F2 (value 5).  Effective: Some(5).
        given ApplicationCode = ApplicationCode.of("presto")
        val token = buildToken(Seq(
          plan("p1", feature("f2")),
          plan("p2", feature("f2", Some(5L))),
        ))
        assertTrue(token.featureValue(FeatureCode.of("f2")) == Some(5L))
      },
      test("featureValue returns None when feature is absent") {
        given ApplicationCode = ApplicationCode.of("presto")
        val token = buildToken(Seq(plan("legacy", feature("tfa"))))
        assertTrue(token.featureValue(FeatureCode.of("not-here")) == None)
      },
      test("Token with no plans grants no features") {
        given ApplicationCode = ApplicationCode.of("presto")
        val token = buildToken(Seq.empty)
        assertTrue(token.features.isEmpty, !token.hasFeature(FeatureCode.of("tfa")), token.featureValue(FeatureCode.of("tfa")) == None)
      },
    )
}
