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
      test("RawUser -> CompactUser (the conversion jwt.scala uses) keeps groups and plans") {
        // Regressão v3.0.0/v3.0.1: o Transformer de morbid.transformers montava o CompactApplication
        // sem os planos, e todo token emitido saía sem features.
        import io.scalaland.chimney.dsl.*
        import morbid.transformers.given
        given ApplicationCode = ApplicationCode.of("presto")

        val ts      = LocalDateTime.now
        val appId   = ApplicationId.of(2)
        val details = buildToken(Seq.empty).user.details
        val ftr     = RawFeature(id = FeatureId.of(1), created = ts, deleted = None, app = appId, code = FeatureCode.of("credentials"), name = FeatureName.of("Credenciais"))
        val pln     = RawPlan(id = PlanId.of(1), created = ts, deleted = None, active = true, app = appId, code = PlanCode.of("default"), name = PlanName.of("Default"), features = Seq(RawPlanFeature(ftr, Some(3L))))
        val role    = RawRole(id = RoleId.of(1), created = ts, deleted = None, code = RoleCode.of("adm"), name = RoleName.of("Admin"))
        val grp     = RawGroup(id = GroupId.of(1), created = ts, deleted = None, code = GroupCode.of("all"), name = GroupName.of("All"), roles = Seq(role))
        val app     = RawApplication(
          details = RawApplicationDetails(id = appId, created = ts, deleted = None, active = true, code = ApplicationCode.of("presto"), name = ApplicationName.of("Presto")),
          groups  = Seq(grp),
          plans   = Seq(pln),
        )

        val user  = RawUser(details, Seq(app)).transformInto[CompactUser]
        val token = Token(created = now, expires = None, user = user)
        val capp  = user.applications.head

        assertTrue(
          capp.plans  == Seq(plan("default", feature("credentials", Some(3L)))),
          capp.groups == Seq(CompactGroup(GroupCode.of("all"), Seq(RoleCode.of("adm")))),
          token.hasFeature(FeatureCode.of("credentials")),
        )
      },
    )
}
