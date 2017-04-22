# Motivation

Nginx does not provide natively LDAP authentication. But it provides a generic
authentication module, that performs HTTP requests to a backend to check if 
a user is allowed to access the ressource
(see [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)).

nginx-auth-ldap provides such a backend to do HTTP Basic Auth on a LDAP backend.

# Install

`go get -u github.com/stephane-martin/nginx-auth-ldap`

The dependencies are vendored.

# Configuration

See [the configuration example](https://github.com/stephane-martin/nginx-auth-ldap/blob/master/nginx-auth-ldap.example.toml).


The configuration directory can be specified by a commandline flag
`--config=XXX` (it defaults to `/etc`).

In that directory, the configuration filename must be `nginx-auth-ldap.toml`.
(Configuration is parsed using [viper](https://github.com/spf13/viper), so other
formats are possible)

It is also possible to configure nginx-auth-ldap through environment variables.
See [conf.go](https://github.com/stephane-martin/nginx-auth-ldap/blob/master/conf/conf.go)
for the mappings.

(So it is possible to store the nginx-auth-ldap into consul.
Use [envconsul](https://github.com/hashicorp/envconsul) to push the configuration.)

# Running

See `nginx-auth-ldap --help`.

# Stopping

Send SIGTERM or SIGINT to the process.

# Reload configuration

Send SIGHUP to the process.

# Nginx configuration example

```nginx
server {
    location /url_to_protect {
        auth_request _auth; 
        proxy_set_header REMOTE_USER $remote_user;
    }

    location = /_auth {
        internal;
        proxy_pass http://A.B.C.D:PORT;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
    }
}
```

# Compatibility

- Nginx needs to be compiled with the `ngx_http_auth_request_module` module.
- Golang >= 1.8 (Due to HTTP Server graceful shutdown)

