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

Consul KV can be used too. Put the parameters under `nginx-auth-ldap/conf`. For
example:

```
consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/conf/cache/expires_seconds 180
consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/conf/http/realm 'My Realm'
nginx-auth-ldap serve --loglevel=debug --consul=http://127.0.0.1:8500
```

When `--consul` is provided, nginx-auth-ldap will watch for changes in Consul
and restart if necessary.


# Running

See `nginx-auth-ldap --help`.

# Stopping

Send SIGTERM or SIGINT to the process.

# Reload configuration

Send SIGHUP to the process.

# Health check

`curl -I http://127.0.0.1:8081/check`

# Stats

Redis is needed to store the requests logs that we use to make the stats. Enable
it in configuration.

Then: `curl http://127.0.0.1:8081/stats`


# Nginx configuration example

```nginx
server {
    location /url_to_protect {
        auth_request _auth; 
        proxy_set_header REMOTE_USER $remote_user;
    }

    location = /_auth {
        internal;
        # A.B.C.D: Listen IP for nginx-auth-ldap
        proxy_pass http://A.B.C.D:PORT;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        # pass some information to nginx-auth-ldap about the incoming request
        # (useful for logs)
        proxy_set_header X-Forwarded-Server $http_host;
        proxy_set_header X-Forwarded-Host $http_host:443;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-Port 443;
        proxy_set_header X-Forwarded-Proto https;

        # you can also cache the results on nginx, if there is a hig latency
        # between the nginx server and the nginx-auth-ldap service.

        # proxy_cache my_auth_zone;
        # proxy_cache_valid 200 5m;
        # proxy_cache_key "$http_authorization";
        # proxy_cache_methods HEAD;
        # proxy_cache_revalidate off;
        # proxy_ignore_headers Cache-Control;

        # ... and define my_auth_zone in a proxy_cache_path

    }
}
```

# Compatibility

- Nginx needs to be compiled with the `ngx_http_auth_request_module` module.
- Golang >= 1.8 (Due to HTTP Server graceful shutdown)
- Should work on *NIX. Not compatible with Windows.


