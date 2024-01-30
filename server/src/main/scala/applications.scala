package morbid

import zio.*

object applications {

  import morbid.types.*
  import morbid.domain.raw.*
  import morbid.repo.Repo

  trait Applications {
    def applicationDetailsGiven (account: AccountCode)                               : Task[Seq[RawApplicationDetails]]
    def applicationGiven        (account: AccountCode, application: ApplicationCode) : Task[Option[RawApplication]]
  }

  object Applications {
    val layer: ZLayer[Repo, Throwable, Applications] = ZLayer.fromFunction(LocalApplications.apply _)
  }

  private case class LocalApplications(repo: Repo) extends Applications {
    override def applicationDetailsGiven(account: AccountCode): Task[Seq[RawApplicationDetails]] = repo.applicationDetailsGiven(account)
    override def applicationGiven(account: AccountCode, application: ApplicationCode): Task[Option[RawApplication]] = repo.applicationGiven(account, application)
  }
}
