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
