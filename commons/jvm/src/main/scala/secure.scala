package morbid

object roles {

  import types.{ApplicationCode, RoleCode}
  import domain.token.{Token, SingleAppToken, HasRoles}

  given Conversion[String, Role] with
    def apply(code: String): Role = SingleRole(RoleCode.of(code))

  sealed trait Role {
    infix def or  (code: String) : Role = or(SingleRole(RoleCode.of(code)))
    infix def or  (code: Role)   : Role = OrRole(this, code)
    infix def and (code: String) : Role = and(SingleRole(RoleCode.of(code)))
    infix def and (code: Role)   : Role = AndRole(this, code)

    def isSatisfiedBy(token: Token)(using ApplicationCode): Boolean
    def isSatisfiedBy(token: SingleAppToken): Boolean
  }

  private case class SingleRole(code: RoleCode) extends Role {
    override def toString = RoleCode.value(code)
    override def isSatisfiedBy(tk: Token)(using ApplicationCode): Boolean = tk.hasRole(code)
    override def isSatisfiedBy(tk: SingleAppToken)              : Boolean = tk.hasRole(code)
  }

  private case class OrRole(r1: Role, r2: Role) extends Role {
    override def toString = s"($r1 || $r2)"
    override def isSatisfiedBy(tk: Token)(using ApplicationCode): Boolean = r1.isSatisfiedBy(tk) || r2.isSatisfiedBy(tk)
    override def isSatisfiedBy(tk: SingleAppToken)              : Boolean = r1.isSatisfiedBy(tk) || r2.isSatisfiedBy(tk)
  }

  private case class AndRole(r1: Role, r2: Role) extends Role {
    override def toString = s"($r1 && $r2)"
    override def isSatisfiedBy(tk: Token)(using ApplicationCode): Boolean = r1.isSatisfiedBy(tk) && r2.isSatisfiedBy(tk)
    override def isSatisfiedBy(tk: SingleAppToken)              : Boolean = r1.isSatisfiedBy(tk) && r2.isSatisfiedBy(tk)
  }
}

object secure {

  import domain.raw.RawUserDetails
  import types.ApplicationCode
  import domain.token.{SingleAppToken, Token}
  import roles.Role
  import guara.utils.Origin
  import guara.errors.*
  import zio.http.*
  import zio.*

  type AppRoute       = (SingleAppToken, ApplicationCode) ?=> Request => Task[Response]
  type TokenValidator = SingleAppToken => Either[String, Unit]

  val AllowAll: TokenValidator = _ => Right(())

  def role(role: Role, allow: TokenValidator = AllowAll)(fn: Request => Task[Response])(request: Request)(using token: SingleAppToken): Task[Response] = {

    def forbidden(message: String) = GuaraError.fail(MorbidError.Forbidden, Status.Forbidden, message)

    def test(token: SingleAppToken): Task[Unit] = {
      if (role.isSatisfiedBy(token)) ZIO.unit
      else                           forbidden(s"Required role '$role' is missing from user token (application: ${token.user.application.code})")
    }

    def execute = {
      def log(maybe: Option[RawUserDetails]) = {
        maybe match
          case Some(imp) => ZIO.logWarning(s"Executing impersonated request at '${request.url.path.encode}' by '${imp.id}/${imp.email}' on behalf of '${token.user.details.id}/${token.user.details.email}' on app '${token.user.application.code}'")
          case None      => ZIO.logInfo   (s"Executing request at '${request.url.path.encode}' by '${token.user.details.id}/${token.user.details.email}' on app '${token.user.application.code}'")
      }

      for
        _      <- log(token.user.impersonatedBy)
        result <- fn(request)
      yield result
    }

    for
      _      <- allow(token) match {
               case Left(err) => forbidden(err)
               case Right(_)  => test(token)
             }
      result <- execute @@ morbid.track.account(token)
    yield result
  }

  def appRoute(application: ApplicationCode, tokenFrom: Request => Task[Token])(route: AppRoute)(request: Request)(using Origin): Task[Response] = {

    def execute(token: SingleAppToken) = {
      given SingleAppToken  = token
      given ApplicationCode = application
      route(request)
    }

    for
      _     <- ZIO.logInfo(s"Executing app route for app '${application}'")
      token <- tokenFrom(request)
      _     <- ZIO.logInfo(s"Token extracted ${token.user.details.email}")
      sat   <- ZIO.fromOption(token.narrowTo(application)).mapError(GuaraError.of(MorbidError.Forbidden, Status.Forbidden, s"User has no access to application '$application'"))
      _     <- ZIO.logInfo(s"Token narrowed. Executing")
      res   <- execute(sat)
    yield res
  }
}