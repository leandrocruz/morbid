package morbid.utils

import guara.http.errors.ReturnResponseWithExceptionError
import morbid.domain.raw.RawUser
import org.apache.commons.lang3.exception.ExceptionUtils
import zio.*
import zio.http.*
import zio.http.Status.InternalServerError
import zio.json.*

type ValidateToken = Request => Task[Unit]