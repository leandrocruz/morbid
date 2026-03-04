package morbid

object lenses {

  import types.*
  import domain.raw.*
  import zio.optics.Lens

  val userDetailsLens = Lens[RawUser, RawUserDetails](
    get = user => Right(user.details),
    set = details => user => Right(user.copy(details = details))
  )

  val idLens = Lens[RawUserDetails, UserId](
    get = details => Right(details.id),
    set = id => details => Right(details.copy(id = id))
  )
}
