0.2.3.0
=======

* Support `hoauth2-1.11.0`
* Drop support for `jose` versions < 0.8
* Expose `decodeKey`
* OAuth2 provider remove a session when an access token expires. It will use a
  refresh token if one is available to create a new session. If no refresh token
  is available it will redirect the user to re-authenticate.
* Providers can define logic for refreshing a session without user intervention.
* Add an OpenID Connect provider.

0.2.2.0
=======

* Add request logging to executable
* Newer multistage Docker build system

0.2.1.0
=======

* Fix a bug in deserialization of `UserIdentity`

0.2.0.0
=======

* Drop compatiblity with hoauth2 versions <= 1.0.0.
* Add a function for getting the oauth2 token from an authenticated request.
* Modify encoding of oauth2 session cookies. As a consequence existing cookies will be invalid.

0.1.2.1
=======

* Compatibility with hoauth2-1.3.0 - fixed: [#4](https://github.com/fpco/wai-middleware-auth/issues/4)

0.1.2.0
=======

* Implemented compatibility with hoauth2 >= 1.0.0 - fixed: [#3](https://github.com/fpco/wai-middleware-auth/issues/3)

0.1.1.2
=======

* Fixed [wai-middleware-auth-0.1.1.1 does not compile in 32 bit Linux](https://github.com/fpco/wai-middleware-auth/issues/2)

0.1.1.1
=======

* Disallow empty `userIdentity` to produce a successfull login.
* Produces a 404 on `/favicon.ico` page if not logged in: work around for issue
  with Chrome requesting it first and messing up the redirect url.
* Added JQuery to the template, since it's bootstrap's requirement.

0.1.1.0
=======

* Fixed whitelist email regex matching for Github and Google auth.

0.1.0.0
=======

* Initial implementation.
