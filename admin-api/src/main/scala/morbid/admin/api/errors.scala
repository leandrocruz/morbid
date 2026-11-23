package morbid.admin.api

import guara.errors.ReturnUnifiedError
import guara.uef.UnifiedErrorFormat
import guara.utils.Origin
import zio.*
import zio.http.Status
import zio.http.codec.{ContentCodec, HttpCodec, HttpCodecError, HttpCodecType, StatusCodec}
import zio.schema.{DeriveSchema, Schema}

sealed trait ApiError {
  def uef: UnifiedErrorFormat
}

object ApiError {

  private val AdminApi = Origin.of("AdminApi")

  private given Schema[Origin]             = Schema[String].transform(Origin.of, _.toString)
  private given Schema[UnifiedErrorFormat] = DeriveSchema.gen

  case class BadInput     (uef: UnifiedErrorFormat) extends ApiError
  case class Unauthorized (uef: UnifiedErrorFormat) extends ApiError
  case class Forbidden    (uef: UnifiedErrorFormat) extends ApiError
  case class NotFound     (uef: UnifiedErrorFormat) extends ApiError
  case class Conflict     (uef: UnifiedErrorFormat) extends ApiError
  case class Upstream     (uef: UnifiedErrorFormat) extends ApiError
  case class Internal     (uef: UnifiedErrorFormat) extends ApiError

  private def uef(message: String, status: Int): UnifiedErrorFormat =
    UnifiedErrorFormat(AdminApi, message, status, Some(status), None)

  def badInput     (message: String): BadInput     = BadInput    (uef(message, 400))
  def unauthorized (message: String): Unauthorized = Unauthorized(uef(message, 401))
  def forbidden    (message: String): Forbidden    = Forbidden   (uef(message, 403))
  def notFound     (message: String): NotFound     = NotFound    (uef(message, 404))
  def conflict     (message: String): Conflict     = Conflict    (uef(message, 409))
  def upstream     (message: String): Upstream     = Upstream    (uef(message, 502))
  def internal     (message: String): Internal     = Internal    (uef(message, 500))

  given Schema[BadInput]     = summon[Schema[UnifiedErrorFormat]].transform(BadInput.apply    , _.uef)
  given Schema[Unauthorized] = summon[Schema[UnifiedErrorFormat]].transform(Unauthorized.apply, _.uef)
  given Schema[Forbidden]    = summon[Schema[UnifiedErrorFormat]].transform(Forbidden.apply   , _.uef)
  given Schema[NotFound]     = summon[Schema[UnifiedErrorFormat]].transform(NotFound.apply    , _.uef)
  given Schema[Conflict]     = summon[Schema[UnifiedErrorFormat]].transform(Conflict.apply    , _.uef)
  given Schema[Upstream]     = summon[Schema[UnifiedErrorFormat]].transform(Upstream.apply    , _.uef)
  given Schema[Internal]     = summon[Schema[UnifiedErrorFormat]].transform(Internal.apply    , _.uef)

  def from(error: Throwable): ApiError = error match
    case rue: ReturnUnifiedError =>
      rue.status match
        case 400 => badInput(rue.message)
        case 401 => unauthorized(rue.message)
        case 403 => forbidden(rue.message)
        case 404 => notFound(rue.message)
        case 409 => conflict(rue.message)
        case 502 => upstream(rue.message)
        case _   => internal(rue.message)
    case _ =>
      internal(s"Internal error: ${error.getMessage}")

  extension [A](task: Task[A]) {
    def api: IO[ApiError, A] =
      task
        .tapError {
          case _: ReturnUnifiedError => ZIO.unit
          case other                 => ZIO.logError(s"Unexpected failure: ${other.getMessage}")
        }
        .mapError(from)
  }

  val uefCodecError: HttpCodec[HttpCodecType.ResponseType, HttpCodecError] =
    (StatusCodec.BadRequest ++ ContentCodec.content[BadInput])
      .transformOrFail[HttpCodecError] { body => Right(HttpCodecError.CustomError("UEF", body.uef.message)) } {
        error => Right(badInput(error.message))
      }
}
