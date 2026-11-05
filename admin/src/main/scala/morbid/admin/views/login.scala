package morbid.admin.views

import com.raquo.airstream.core.EventStream
import com.raquo.laminar.api.L.*
import medulla.fetch.Fetcher
import medulla.firebase.{FirebaseAuth, JWToken, SAMLAuthProvider}
import medulla.ui.inputs.{InputType, InputVar, given}
import medulla.ui.{Buttons, Input}
import morbid.admin.*
import morbid.admin.api.*
import morbid.admin.codec.given
import morbid.types.*
import org.scalajs.dom.window

import scala.concurrent.ExecutionContext.Implicits.global
import scala.util.{Failure, Success, Try}

object LoginView {

  private enum Mode:
    case EnterEmail
    case Password(provider: GetProviderResponse)
    case Saml    (provider: GetProviderResponse)

  def render(using dict: Dictionary, fetcher: Fetcher): HtmlElement = {

    val emailVar    = InputVar.of[String]
    val passwordVar = InputVar.of[String]
    val mode        = Var[Mode](Mode.EnterEmail)
    val submitting  = Var(false)
    val error       = Var(Option.empty[String])

    val continueTrigger = EventBus[Unit]()
    val loginTrigger    = EventBus[Unit]()
    val ssoTrigger      = EventBus[String]()

    def resetError(): Unit = error.set(None)

    def firebaseEmailPassword(email: String, password: String): EventStream[Try[JWToken]] =
      EventStream.fromFuture {
        FirebaseAdmin.engine.login { auth =>
          FirebaseAuth.signInWithEmailAndPassword(auth, email, password).toFuture
        }
      }.recoverToTry

    def firebaseSaml(providerId: String): EventStream[Try[JWToken]] =
      EventStream.fromFuture {
        FirebaseAdmin.engine.login { auth =>
          FirebaseAuth.signInWithPopup(auth, new SAMLAuthProvider(providerId)).toFuture
        }
      }.recoverToTry

    def completeLogin(tokenTry: Try[JWToken]): EventStream[Unit] = tokenTry match
      case Failure(_) =>
        submitting.set(false)
        error.set(Some(dict.loginErrorGeneric))
        EventStream.empty
      case Success(token) =>
        fetcher.execute(Endpoints.login(LoginRequest(JWToken.unwrap(token)))).map {
          case Success(_)   =>
            submitting.set(false)
            window.location.reload()
          case Failure(err) =>
            submitting.set(false)
            error.set(Some(errorMessage(err, dict)))
        }

    val continueFlow: EventStream[Unit] = continueTrigger.events.flatMapSwitch { _ =>
      submitting.set(true)
      resetError()
      emailVar.now match
        case Some(em) if em.nonEmpty =>
          fetcher.execute(Endpoints.getProvider(GetProviderRequest(Email.of(em)))).map {
            case Success(resp) =>
              submitting.set(false)
              resp.`type` match
                case LoginMode.up   => mode.set(Mode.Password(resp))
                case LoginMode.saml => mode.set(Mode.Saml(resp))
            case Failure(_)    =>
              submitting.set(false)
              error.set(Some(dict.loginProviderError))
          }
        case _ =>
          submitting.set(false)
          error.set(Some(dict.loginProviderError))
          EventStream.empty
    }

    val passwordFlow: EventStream[Unit] = loginTrigger.events.flatMapSwitch { _ =>
      submitting.set(true)
      resetError()
      (emailVar.now, passwordVar.now) match
        case (Some(em), Some(pw)) if em.nonEmpty && pw.nonEmpty =>
          firebaseEmailPassword(em, pw).flatMapSwitch(completeLogin)
        case _ =>
          submitting.set(false)
          error.set(Some(dict.loginErrorGeneric))
          EventStream.empty
    }

    val ssoFlow: EventStream[Unit] = ssoTrigger.events.flatMapSwitch { providerId =>
      submitting.set(true)
      resetError()
      firebaseSaml(providerId).flatMapSwitch(completeLogin)
    }

    def emailField(disabled0: Boolean) = div(
      label(cls("block text-sm font-medium text-admin-text mb-1"), dict.loginEmail),
      Input.basic(emailVar).node.amend(
        typ("email"),
        autoFocus(!disabled0),
        disabled(disabled0),
      )
    )

    def passwordField = div(
      label(cls("block text-sm font-medium text-admin-text mb-1"), dict.loginPassword),
      Input.basic(passwordVar, kind = Signal.fromValue(InputType.password)).node.amend(autoFocus(true))
    )

    def cancelButton = Buttons.secondary.amend(
      cls("w-full"),
      typ("button"),
      dict.loginCancel,
      onClick --> { _ =>
        passwordVar.set(None)
        resetError()
        mode.set(Mode.EnterEmail)
      }
    )

    def continueButton = Buttons.primary.amend(
      cls("w-full"),
      typ("submit"),
      disabled <-- submitting.signal,
      child.text <-- submitting.signal.map(b => if b then dict.loading else dict.loginContinue),
    )

    def submitPasswordButton = Buttons.primary.amend(
      cls("w-full"),
      typ("submit"),
      disabled <-- submitting.signal,
      child.text <-- submitting.signal.map(b => if b then dict.loading else dict.loginButton),
    )

    def ssoButton(provider: GetProviderResponse) = {
      val label = provider.name.map(n => s"${dict.loginSso} — $n").getOrElse(dict.loginSso)
      Buttons.primary.amend(
        cls("w-full"),
        typ("button"),
        disabled <-- submitting.signal,
        child.text <-- submitting.signal.map(b => if b then dict.loading else label),
        onClick --> { _ =>
          provider.id.foreach(ssoTrigger.emit)
        },
      )
    }

    def errorView = child.maybe <-- error.signal.map(_.map(msg =>
      div(cls("text-sm text-admin-error-fg text-center"), msg)
    ))

    def renderForm(current: Mode): HtmlElement = current match
      case Mode.EnterEmail =>
        form(
          cls("flex flex-col gap-4"),
          onSubmit.preventDefault --> { _ => continueTrigger.emit(()) },
          emailField(disabled0 = false),
          errorView,
          div(cls("mt-2"), continueButton),
        )

      case Mode.Password(_) =>
        form(
          cls("flex flex-col gap-4"),
          onSubmit.preventDefault --> { _ => loginTrigger.emit(()) },
          emailField(disabled0 = true),
          passwordField,
          errorView,
          div(cls("mt-2 flex flex-col gap-2"), submitPasswordButton, cancelButton),
        )

      case Mode.Saml(provider) =>
        div(
          cls("flex flex-col gap-4"),
          emailField(disabled0 = true),
          errorView,
          div(cls("mt-2 flex flex-col gap-2"), ssoButton(provider), cancelButton),
        )

    div(
      cls("flex items-center justify-center min-h-screen bg-admin-bg"),
      continueFlow --> Observer.empty,
      passwordFlow --> Observer.empty,
      ssoFlow      --> Observer.empty,
      div(
        cls("login-card"),
        div(
          cls("text-center mb-8"),
          div(cls("font-mono font-bold text-2xl text-admin-text mb-2"), dict.loginTitle),
          div(cls("text-sm text-admin-muted"), dict.loginSubtitle),
        ),
        child <-- mode.signal.map(renderForm),
      )
    )
  }

  private def errorMessage(err: Throwable, dict: Dictionary): String = err.getMessage match {
    case msg if msg.contains("403")                                             => dict.accessOnlyRoot
    case msg if msg.contains("401") || msg.toLowerCase.contains("unauthorized") => dict.loginErrorGeneric
    case msg                                                                    => msg
  }
}
