# wai-middleware-auth

[![Build Status](https://dev.azure.com/fpco/wai-middleware-auth/_apis/build/status/fpco.wai-middleware-auth?branchName=master)](https://dev.azure.com/fpco/wai-middleware-auth/_build/latest?definitionId=4&branchName=master)

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

Along with middleware this package ships with an executable `wai-auth`, which
can function as a protected file server or a reverse proxy. Right from the box
it supports OAuth2 authentication as well as it's custom implementations for
Google and Github.

Configuration is done using a yaml config file. Here is a sample file that will
configure `wai-auth` to run a file server with Google, GitHub, and GitLab
authentication on `http://localhost:3000`:

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
  gitlab:
    client_id: "...9cfc"
    client_secret: "...f0d0"
    app_name: "Dev App for wai-middleware-auth"
    email_white_list:
      - "^[a-zA-Z0-9._%+-]+@example.com$"
```

Above configuration will also block access to users that don't have an email
with `example.com` domain. There is also a `secret_key` field which will be used
to encrypt the session cookie. In order to generate a new random key run this command:

```shell
$ echo $(wai-auth key --base64)
azuCFq0zEBkLSXhQrhliZzZD8Kblo...
```

Make sure you have proper callback/redirect urls registered with
google/github/gitlab apps, eg:
`http://localhost:3000/_auth_middleware/google/complete`.

After configuration file is ready, running application is very easy:

```shell
$ wai-auth --config-file=/path/to/config.yaml
Listening on port 3000
```

### Reverse proxy

To use a reverse proxy instead of a file server, replace `file_server` with
`reverse_proxy`, eg:

```yaml
reverse_proxy:
  host: myapp.example.com
  port: 80
```

### Self-hosted GitLab

The GitLab provider also supports using a self-hosted GitLab instance by
setting the `gitlab_host` field.  In this case you may also want to override
the `provider_info` to change the title, logo, and description.  For example:

```yaml
providers:
  gitlab:
    gitlab_host: gitlab.mycompany.com
    client_id: "...9cfc"
    client_secret: "...f0d0"
    app_name: "Dev App for wai-middleware-auth"
    email_white_list:
      - "^[a-zA-Z0-9._%+-]+@mycompany.com$"
    provider_info:
      title: My Company's GitLab
      logo_url: https://mycompany.com/logo.png
      descr: Use your My Company GitLab account to access this page.
```
