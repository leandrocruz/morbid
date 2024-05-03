package morbid

import morbid.types.*
import morbid.domain.raw.*
import morbid.domain.token.Token
import zio.test.Assertion.*
import zio.test.*
import roles.given

import java.time.{LocalDateTime, ZonedDateTime}

object RoleSpec extends ZIOSpecDefault {


  def token(groups: Seq[RawGroup]) = Token(
    created = ZonedDateTime.now(),
    expires = None,
    impersonatedBy = None,
    user = RawUser(
      details = RawUserDetails(
        id          = UserId.of(1),
        created     = LocalDateTime.now(),
        deleted     = None,
        tenant      = TenantId.of(1),
        tenantCode  = TenantCode.of("t1"),
        account     = AccountId.of(1),
        accountCode = AccountCode.of("acc1"),
        kind        = None,
        active      = true,
        code        = UserCode.of("u1"),
        email       = Email.of("u1@a1.com")
      ),
      applications = Seq (
        RawApplication(
          details = RawApplicationDetails(id = ApplicationId.of(1), created = LocalDateTime.now(), deleted = None, active = true, code = ApplicationCode.of("app1"), name = ApplicationName.of("App One")),
          groups  = groups
        )
      )

    )
  )

  def spec =
    suite("RoleSpec") (
      test("role boolean expression")  {
        given ApplicationCode = ApplicationCode.of("app1")

        val r1 = RawRole  (id = RoleId.of(1) , created = LocalDateTime.now(), deleted = None, code = RoleCode.of("r1") , name = RoleName.of("Role 1")  , permissions = Seq.empty)
        val r2 = RawRole  (id = RoleId.of(2) , created = LocalDateTime.now(), deleted = None, code = RoleCode.of("r2") , name = RoleName.of("Role 2")  , permissions = Seq.empty)
        val g1 = RawGroup (id = GroupId.of(1), created = LocalDateTime.now(), deleted = None, code = GroupCode.of("g1"), name = GroupName.of("Group 1"), roles = Seq(r1, r2))

        assertTrue {    "r1"             isSatisfiedBy token(Seq(g1))  }
        assertTrue {    "r2"             isSatisfiedBy token(Seq(g1))  }
        assertTrue { ! ("other"          isSatisfiedBy token(Seq(g1))) }
        assertTrue {    "r1" or "r2"     isSatisfiedBy token(Seq(g1))  }
        assertTrue {    "r1" or "other"  isSatisfiedBy token(Seq(g1))  }
        assertTrue {    "r1" and "r2"    isSatisfiedBy token(Seq(g1))  }
        assertTrue { ! ("r1" and "other" isSatisfiedBy token(Seq(g1))) }

      }
    )

}