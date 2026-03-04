package morbid

object roles {

  import types.{ApplicationCode, RoleCode}
  import domain.token.{Token, SingleAppToken, HasRoles}

  given Conversion[String, Role] with
    def apply(code: String): Role = SingleRole(RoleCode.of(code))

  sealed trait Role {
    def or  (code: String) : Role = or(SingleRole(RoleCode.of(code)))
    def or  (code: Role)   : Role = OrRole(this, code)
    def and (code: String) : Role = and(SingleRole(RoleCode.of(code)))
    def and (code: Role)   : Role = AndRole(this, code)

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
