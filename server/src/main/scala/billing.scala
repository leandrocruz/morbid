package morbid


object billing {

  import zio.*
  import morbid.domain.raw.RawAccount
  import morbid.types.{AccountCode, ApplicationCode}
  import morbid.repo.Repo

  trait Billing {
    def usersByAccount(app: ApplicationCode): Task[Map[RawAccount, Int]]
  }

  object Billing {
    val layer = ZLayer.fromFunction(SimpleBilling.apply _)
  }

  case class SimpleBilling(repo: Repo) extends Billing {
    override def usersByAccount(app: ApplicationCode): Task[Map[RawAccount, Int]] = ??? // repo.exec(ReportUsersByAccount(app))
  }
}