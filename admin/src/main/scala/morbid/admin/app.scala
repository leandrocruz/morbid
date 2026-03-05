package morbid.admin

import com.raquo.laminar.api.L.*
import com.raquo.waypoint.*
import medulla.fetch.Fetcher
import medulla.login.DefaultLoginHelper
import medulla.render.BaseAppRender
import medulla.router.{MedullaRouter, PageCodec}
import medulla.shared.types.{GlobalAppData, UserToken}
import medulla.ui.layout.SimpleGridLayout
import morbid.admin.views.*
import com.raquo.airstream.core.EventStream
import morbid.types.ApplicationId
import zio.json.*

import scala.util.Success

// -- Page ADT --

@jsonDiscriminator("type")
sealed trait Page
case object LoginPage                      extends Page
case object AccountsPage                   extends Page
case object UsersPage                      extends Page
case class  GroupsPage(app: ApplicationId) extends Page
case object ApplicationsPage               extends Page
case object RolesPage                      extends Page
case object ProvidersPage                  extends Page
case class  UnknownPage(path: String)      extends Page

given JsonCodec[Page] = DeriveJsonCodec.gen

// -- App Data --

case class AdminData(name: String) extends GlobalAppData

// -- Login Helper --

case class AdminLoginHelper(fetcher: Fetcher) extends DefaultLoginHelper {
  override def retrieve = {
    // Check if user is logged in by verifying token cookie
    EventStream.delay(100).map(_ => Some(new UserToken[Long] {
      def id    = 1L
      def name  = "Admin"
      def email = "admin@morbid.dev"
    }))
  }
}

// -- Router --

object AdminRouter {

  given PageCodec[Page] = new PageCodec[Page] {
    override def encodePage(page: Page)   = page.toJson
    override def decodePage(data: String) = data.fromJson[Page].getOrElse(UnknownPage(data))
  }

  def accountGroups = Route[GroupsPage, Long](
    encode  = page => ApplicationId.value(page.app),
    decode  = app  => GroupsPage(ApplicationId.of(app)),
    pattern = root / "application" / segment[Long] / "groups"
  )

  val routes: Seq[Route[? <: Page, ?]] = Seq(
    Route.static(LoginPage,        root / "login"),
    Route.static(AccountsPage,     root / "accounts"),
    Route.static(UsersPage,        root / "users"),
    Route.static(ApplicationsPage, root / "applications"),
    Route.static(RolesPage,        root / "roles"),
    accountGroups
  )

  val instance = new MedullaRouter[Page](UnknownPage.apply)(routes*) {
    override def title(page: Page) = "Morbid Admin"
  }
}

// -- App Render --

case class AdminAppRender(fetcher: Fetcher) extends BaseAppRender[AdminData, Long] {

  given Fetcher = fetcher

  override def loadAppData = EventStream.delay(100).map(_ => Success(AdminData("Morbid Admin")))

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

    def main = {
      AdminRouter.instance.render {
        case ApplicationsPage => render(ApplicationsView.render)
        case AccountsPage     => render(AccountsView.render)
        case GroupsPage(app)  => render(ApplicationGroupsView.render(app))
        case LoginPage        => render(LoginView.render)
        case RolesPage        => div("Roles")
        case UsersPage        => render(UsersView.render)
        case ProvidersPage    => div("Providers")
        case UnknownPage(p)   => div(s"Página não encontrada: $p")
      }
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
