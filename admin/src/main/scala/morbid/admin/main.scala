package morbid.admin

import com.raquo.laminar.api.L.renderOnDomContentLoaded
import medulla.config.MedullaConfig
import medulla.fetch.*
import medulla.login.{LocalLogout, LoginHelper, Logout}
import medulla.render.AppRender
import medulla.{DefaultMedullaApp, MedullaApp, config}
import org.scalajs.dom.{document, window}
import wvlet.airframe.*

@main
def main(): Unit = {

  type UID = Long

  val backendUrl = window.location.host match {
    case "localhost:5173" | "127.0.0.1:5173" => "" // vite proxy handles /api
    case _                                   => s"${window.location.protocol}//${window.location.host}"
  }

  val medullaConfig = config.DefaultMedullaConfig(
    name  = "Morbid Admin",
    fetch = config.FetchConfig(backendUrl),
    login = config.LoginConfig(10000),
  )

  newDesign
    .bind [MedullaConfig   ] .toInstance(medullaConfig)
    .bind [Logout]           .to[LocalLogout]
    .bind [Handler]          .toProvider { (logout: Logout) => LogHandler(AuthAwareHandler[UID](JsonHandler(), logout)) }
    .bind [Fetcher]          .to[BasicFetcher]
    .bind [LoginHelper[UID]] .to[AdminLoginHelper]
    .bind [AppRender  [UID]] .to[AdminAppRender]
    .bind [MedullaApp      ] .to[DefaultMedullaApp[UID]]
    .build[MedullaApp] { app =>
      lazy val container = document.getElementById("app")
      renderOnDomContentLoaded(container, app.rootElement)
    }
}
