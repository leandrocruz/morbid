package morbid.admin

import medulla.firebase.{FirebaseConfig, FirebaseEngine, FirebaseOptions, InMemoryFirebaseEngine}
import org.scalajs.dom.window

object FirebaseAdmin {

  private val firebaseDevOptions = new FirebaseOptions {
    override val appId             = "1:719515434696:web:18fb755c29a23762f06ffd"
    override val apiKey            = "AIzaSyANn8f6bvWqQ1jQWm13fA6cS9LqfdmB25U"
    override val authDomain        = "presto-dev-env-1.firebaseapp.com"
    override val projectId         = "presto-dev-env-1"
    override val storageBucket     = "presto-dev-env-1.appspot.com"
    override val messagingSenderId = "719515434696"
  }

  private val firebaseProdOptions = new FirebaseOptions {
    override val appId             = "1:48027740555:web:e3b19769c605ebb774678e"
    override val apiKey            = "AIzaSyAsUt1cL6SEFg4Ce0F55rXkMXwMGL-pdvs"
    override val authDomain        = "oystr-presto-test.firebaseapp.com"
    override val projectId         = "oystr-presto-test"
    override val storageBucket     = "oystr-presto-test.appspot.com"
    override val messagingSenderId = "48027740555"
  }

  private def optionsForHost: FirebaseOptions = window.location.host match {
    case "localhost:5173" | "127.0.0.1:5173" => firebaseDevOptions
    case h if h.contains("dev")              => firebaseDevOptions
    case _                                   => firebaseProdOptions
  }

  private val adminConfig = new FirebaseConfig {
    override def name    = "MorbidAdmin"
    override def options = optionsForHost
  }

  val engine: FirebaseEngine = InMemoryFirebaseEngine(adminConfig)
}
