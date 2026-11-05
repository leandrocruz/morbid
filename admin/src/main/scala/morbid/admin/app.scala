package morbid.admin

import com.raquo.airstream.core.EventStream
import com.raquo.laminar.api.L.*
import com.raquo.waypoint.*
import medulla.fetch.Fetcher
import medulla.login.DefaultLoginHelper
import medulla.render.BaseAppRender
import medulla.router.{MedullaRouter, PageCodec}
import medulla.shared.types.{GlobalAppData, UserToken}
import medulla.ui.layout.SimpleGridLayout
import morbid.admin.api.*
import morbid.admin.api.codecs.given
import morbid.admin.codec.given
import morbid.admin.views.*
import morbid.types.{AccountId, ApplicationCode}
import zio.json.*

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success}

// -- Page ADT --

@jsonDiscriminator("type")
sealed trait Page
case object LoginPage                          extends Page
case object DashboardPage                      extends Page
case object AccountsPage                       extends Page
case class  AccountUsersPage(acc: AccountId)   extends Page
case object UsersPage                          extends Page
case class  GroupsPage(app: ApplicationCode)   extends Page
case object ApplicationsPage                   extends Page
case object RolesPage                          extends Page
case object ProvidersPage                      extends Page
case class  UnknownPage(path: String)          extends Page

given JsonCodec[Page] = DeriveJsonCodec.gen

// -- App Data --

case class AdminData(me: LoginResponse) extends GlobalAppData

// -- Login Helper --

case class AdminLoginHelper(fetcher: Fetcher) extends DefaultLoginHelper {

  override def isLoggedIn = {
    // Always try to resolve the session: the cookie is HttpOnly and not visible from JS.
    // retrieve() will return None if the admin-api rejects the current cookie.
    true
  }

  override def retrieve = {
    fetcher.execute(Endpoints.whoami).map {
      case Success(login) =>
        Some(new UserToken[Long] {
          override def id    = AccountId.value(login.account)
          override def name  = login.name.getOrElse(morbid.types.Email.value(login.email))
          override def email = morbid.types.Email.value(login.email)
        })
      case Failure(_) => None
    }
  }
}

// -- Router --

object AdminRouter {

  given PageCodec[Page] = new PageCodec[Page] {
    override def encodePage(page: Page)   = page.toJson
    override def decodePage(data: String) = data.fromJson[Page].getOrElse(UnknownPage(data))
  }

  def groupsRoute = Route[GroupsPage, String](
    encode  = page => ApplicationCode.value(page.app),
    decode  = app  => GroupsPage(ApplicationCode.of(app)),
    pattern = root / "app" / segment[String] / "groups"
  )

  def accountUsersRoute = Route[AccountUsersPage, Long](
    encode  = page => AccountId.value(page.acc),
    decode  = acc  => AccountUsersPage(AccountId.of(acc)),
    pattern = root / "accounts" / segment[Long] / "users"
  )

  val routes: Seq[Route[? <: Page, ?]] = Seq(
    Route.static(LoginPage,        root / "login"),
    Route.static(DashboardPage,    root / endOfSegments),
    Route.static(AccountsPage,     root / "accounts"),
    Route.static(UsersPage,        root / "users"),
    Route.static(ApplicationsPage, root / "applications"),
    Route.static(RolesPage,        root / "roles"),
    Route.static(ProvidersPage,    root / "providers"),
    groupsRoute,
    accountUsersRoute,
  )

  val instance = new MedullaRouter[Page](UnknownPage.apply)(routes*) {
    override def title(page: Page) = "Morbid Admin"
  }
}

// -- App Render --

case class AdminAppRender(fetcher: Fetcher) extends BaseAppRender[AdminData, Long] {

  given Fetcher = fetcher

  override def loadAppData = fetcher.execute(Endpoints.whoami).map(_.map(AdminData.apply))

  private def render(fn: Dictionary ?=> HtmlElement) = {
    div(
      cls("contents"),
      child <-- I18n.dictionary.map { dict =>
        given Dictionary = dict
        fn
      }
    )
  }

  override def whenLoggedOut = render(LoginView.render)

  override def appLoaded(data: AdminData)(using user: UserToken[Long]) = {

    def main = AdminRouter.instance.render {
      case DashboardPage          => render(DashboardView.render)
      case ApplicationsPage       => render(ApplicationsView.render)
      case AccountsPage           => render(AccountsView.render)
      case AccountUsersPage(acc)  => render(UsersView.renderForAccount(acc))
      case GroupsPage(appCode)    => render(GroupsView.render(appCode))
      case LoginPage              => render(LoginView.render)
      case RolesPage              => render(RolesListView.render)
      case UsersPage              => render(UsersView.renderAll)
      case ProvidersPage          => div("Providers")
      case UnknownPage(p)         => div(s"Página não encontrada: $p")
    }

    def left = I18n.dictionary.map { dict =>
      given Dictionary = dict
      Sidebar.render
    }

    def logo = Signal.fromValue(
      div(cls("admin-logo"), "Morbid")
    )

    def top = I18n.dictionary.map { dict =>
      given Dictionary = dict
      TopBar.render
    }

    SimpleGridLayout(logo, top, left, main).render
  }
}
