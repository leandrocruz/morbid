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
import morbid.types.{AccountId, ApplicationCode, GroupCode}
import org.scalajs.dom
import zio.json.*

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

// -- Page ADT --

@jsonDiscriminator("type")
sealed trait Page
case object LoginPage                             extends Page
case object DashboardPage                         extends Page
case object AccountsPage                          extends Page
case class  AccountUsersPage    (acc: AccountId)  extends Page
case class  AccountProvidersPage(acc: AccountId)  extends Page
case class  AccountApiKeysPage  (acc: AccountId)  extends Page
case class  AccountAppsPage     (acc: AccountId)  extends Page
case class  AccountGroupsPage   (acc: AccountId)  extends Page
case class  GroupUsersPage      (acc: AccountId, app: ApplicationCode, grp: GroupCode) extends Page
case class  AppRolesPage(app: ApplicationCode)    extends Page
case object ApplicationsPage                      extends Page
case object TenantsPage                           extends Page
case class  UnknownPage(path: String)             extends Page

given JsonCodec[Page] = DeriveJsonCodec.gen

// -- Session --

/** Caller-scope globals set once at login. The admin must pick an application to
  * work on: every protected admin-api call forwards it via `X-Admin-App`, and
  * admin-role gating is evaluated against that chosen app. */
object Session {

  private val SelectedAppKey = "morbid-admin-selected-app"

  /** Apps the signed-in admin can see (from the login response). */
  val apps: Var[List[AppAccess]] = Var(List.empty)

  /** The signed-in admin's own account (from the login response). */
  val account: Var[Option[AccountId]] = Var(None)

  /** The app the admin is currently working on; `None` until one is picked. */
  val selectedApp: Var[Option[ApplicationCode]] = Var(readSelectedFromStorage)

  /** Admin role on the currently selected app. Views gate CRUD controls on this. */
  val isAdmin: Signal[Boolean] = selectedApp.signal.combineWith(apps.signal).map { (sel, all) =>
    sel.exists(code => all.exists(a => a.code == code && a.isAdmin))
  }

  /** Seed state from a /me or /login response and auto-select if sensible. */
  def initFromLogin(response: LoginResponse): Unit = {
    apps.set(response.apps)
    account.set(Some(response.account))
    val current = selectedApp.now()
    val available = response.apps.map(_.code)
    val next = current match {
      case Some(code) if available.contains(code) => Some(code)
      case _ =>
        response.apps.filter(_.isAdmin) match {
          case singleton :: Nil => Some(singleton.code)
          case _                => None
        }
    }
    setSelectedApp(next)
  }

  def setSelectedApp(code: Option[ApplicationCode]): Unit = {
    selectedApp.set(code)
    Try {
      code match {
        case Some(c) => dom.window.localStorage.setItem(SelectedAppKey, ApplicationCode.value(c))
        case None    => dom.window.localStorage.removeItem(SelectedAppKey)
      }
    }
  }

  private def readSelectedFromStorage: Option[ApplicationCode] =
    Try(Option(dom.window.localStorage.getItem(SelectedAppKey))).toOption.flatten
      .filter(_.nonEmpty)
      .map(ApplicationCode.of)
}

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

  def accountGroupsRoute = Route[AccountGroupsPage, Long](
    encode  = page => AccountId.value(page.acc),
    decode  = acc  => AccountGroupsPage(AccountId.of(acc)),
    pattern = root / "accounts" / segment[Long] / "groups"
  )

  def groupUsersRoute = Route[GroupUsersPage, (Long, String, String)](
    encode  = page => (AccountId.value(page.acc), ApplicationCode.value(page.app), GroupCode.value(page.grp)),
    decode  = { case (acc, app, grp) => GroupUsersPage(AccountId.of(acc), ApplicationCode.of(app), GroupCode.of(grp)) },
    pattern = root / "accounts" / segment[Long] / "apps" / segment[String] / "groups" / segment[String] / "users"
  )

  def appRolesRoute = Route[AppRolesPage, String](
    encode  = page => ApplicationCode.value(page.app),
    decode  = app  => AppRolesPage(ApplicationCode.of(app)),
    pattern = root / "app" / segment[String] / "roles"
  )

  def accountUsersRoute = Route[AccountUsersPage, Long](
    encode  = page => AccountId.value(page.acc),
    decode  = acc  => AccountUsersPage(AccountId.of(acc)),
    pattern = root / "accounts" / segment[Long] / "users"
  )

  def accountProvidersRoute = Route[AccountProvidersPage, Long](
    encode  = page => AccountId.value(page.acc),
    decode  = acc  => AccountProvidersPage(AccountId.of(acc)),
    pattern = root / "accounts" / segment[Long] / "providers"
  )

  def accountApiKeysRoute = Route[AccountApiKeysPage, Long](
    encode  = page => AccountId.value(page.acc),
    decode  = acc  => AccountApiKeysPage(AccountId.of(acc)),
    pattern = root / "accounts" / segment[Long] / "api-keys"
  )

  def accountAppsRoute = Route[AccountAppsPage, Long](
    encode  = page => AccountId.value(page.acc),
    decode  = acc  => AccountAppsPage(AccountId.of(acc)),
    pattern = root / "accounts" / segment[Long] / "apps"
  )

  val routes: Seq[Route[? <: Page, ?]] = Seq(
    Route.static(LoginPage,        root / "login"),
    Route.static(DashboardPage,    root / endOfSegments),
    Route.static(AccountsPage,     root / "accounts"),
    Route.static(ApplicationsPage, root / "applications"),
    Route.static(TenantsPage,      root / "tenants"),
    accountGroupsRoute,
    groupUsersRoute,
    appRolesRoute,
    accountUsersRoute,
    accountProvidersRoute,
    accountApiKeysRoute,
    accountAppsRoute,
  )

  val instance = new MedullaRouter[Page](UnknownPage.apply)(routes*) {
    override def title(page: Page) = "Morbid Admin"
  }
}

// -- App Render --

case class AdminAppRender(fetcher: Fetcher) extends BaseAppRender[AdminData, Long] {

  given Fetcher = fetcher

  override def loadAppData = fetcher.execute(Endpoints.whoami).map { tried =>
    tried.map { login =>
      Session.initFromLogin(login)
      AdminData(login)
    }
  }

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
      case DashboardPage              => render(DashboardView.render)
      case ApplicationsPage           => render(ApplicationsView.render)
      case AccountsPage               => render(AccountsView.render)
      case AccountUsersPage    (acc)  => render(UsersView.renderForAccount(acc))
      case AccountProvidersPage(acc)  => render(ProvidersView.render(acc))
      case AccountApiKeysPage  (acc)  => render(ApiKeysView.render(acc))
      case AccountAppsPage     (acc)  => render(AccountAppsView.render(acc))
      case AccountGroupsPage   (acc)  => render(GroupsView.render(acc))
      case GroupUsersPage(acc, a, g)  => render(GroupUsersView.render(acc, a, g))
      case AppRolesPage(appCode)      => render(RolesListView.render(appCode))
      case LoginPage                  => render(LoginView.render)
      case TenantsPage                => render(TenantsView.render)
      case UnknownPage(p)             => div(s"Página não encontrada: $p")
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
      TopBar.render(using dict, user, fetcher)
    }

    SimpleGridLayout(logo, top, left, main).render
  }
}
