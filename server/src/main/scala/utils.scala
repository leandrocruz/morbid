package morbid.utils

import guara.http.errors.ReturnResponseWithExceptionError
import morbid.domain.raw.RawUser
import org.apache.commons.lang3.exception.ExceptionUtils
import zio.*
import zio.http.Status.InternalServerError
import zio.http.*
import zio.json.*

type ValidateToken = Request => Task[Unit]

case class CommonError(
  origin  : String,
  code    : Int,
  message : String,
  request : Option[String] = None,
  trace   : Option[String] = None
)

given JsonCodec[CommonError] = DeriveJsonCodec.gen

extension [T](task: Task[Option[T]])
  def orFail(message: String): Task[T] = {
    for
      maybe <- task
      value <- ZIO.fromOption(maybe).mapError(_ => Exception(message))
    yield value
  }

extension [T](task: Task[T]) {
  def refineError(message: String): Task[T] = task.mapError(Exception(message, _))

  def errorToResponse(response: Response) = task.mapError(ReturnResponseWithExceptionError(_, response))

  def asCommonError(code: Int, msg: String) = {
    def response(error: Throwable) = Response(
      status  = InternalServerError,
      headers = Headers(Header.Custom("X-Error-Type", "GCEv0") /* Guara Common Error = GCEv0 */),
      body    = Body.fromString(CommonError(origin = "Morbid", code, message = msg, trace = Some(ExceptionUtils.getStackTrace(error))).toJson)
    )
    task.mapError(e => ReturnResponseWithExceptionError(e, response(e)))
  }
}

extension [T](op: Option[T])
  def orFail(message: String): Task[T] = ZIO.fromOption(op).mapError(_ => Exception(message))
