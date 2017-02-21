# wai-middleware-auth

Middleware that secures WAI application

## Installation

```shell
$ stack install wai-middleware-auth
```
OR
```shell
$ cabal install wai-middleware-auth
```

## wai-auth

Along with middleware this package ships with an executbale `wai-auth`, which
can function as a protected file server or a reverse proxy. Right from the box
it supports OAuth2 authentication as well as it's custom implementations for
Google and Github.

Configuration is done using a yaml config file. Here is a sample file that will
configure `wai-auth` to run a file server with google and github authentication
on `http://localhost:3000`:

```yaml
app_root: "_env:APPROOT:http://localhost:3000"
app_port: 3000
cookie_age: 3600
secret_key: "...+vwscbKR4DyPT"
file_server:
  root_folder: "/path/to/html/files"
  redirect_to_index: true
  add_trailing_slash: true
providers:
  github:
    client_id: "...94cc"
    client_secret: "...166f"
    app_name: "Dev App for wai-middleware-auth"
    email_white_list:
      - "^[a-zA-Z0-9._%+-]+@example.com$"
  google:
    client_id: "...qlj.apps.googleusercontent.com"
    client_secret: "...oxW"
    email_white_list:
      - "^[a-zA-Z0-9._%+-]+@example.com$"
```

Above configuration will also block access to users that don't have an email
with `example.com` domain. There is also a `secret_key` field which will be used
to encrypt the session cookie. In order to generate a new random key run this command:

```shell
$ echo $(stack exec -- wai-auth key --base64)
azuCFq0zEBkLSXhQrhliZzZD8Kblo...
```

Make sure you have proper callback/redirect urls registered with google/github
apps, eg: `http://localhost:3000/_auth_middleware/google/complete` After
configuration file is ready, running application is very easy:

```shell
$ wai-auth --config-file=/path/to/config.yaml
Listening on port 3000
```

