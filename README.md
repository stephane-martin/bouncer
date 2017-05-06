# Motivation

Nginx does not provide natively LDAP authentication. But it provides a generic
authentication module, that performs HTTP requests to a backend to check if 
a user is allowed to access the ressource
(see [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)).

nginx-auth-ldap provides such a backend to do HTTP Basic Auth on a LDAP backend.

# Features

## Consul integration

- nginx-auth-ldap configuration can be defined in Consul KV
- if your LDAP directories are services registered in Consul, nginx-auth-ldap can find them
- nginx-auth-ldap can register itself as a Consul service

## LDAP authentication

nginx-auth-ldap can authenticate users based on a LDAP directory. Two authentication
schemes are supported: "direct LDAP bind" or "LDAP search and bind".

Multiple LDAP directories can be defined. In that case, nginx-auth-ldap will
load-balance the LDAP requests among them.

## Backend services

Your backend services don't have to deal with authentication anymore. Instead
they rely on nginx and nginx-auth-ldap to perform the authentication separately.
The services are given information about the current user by HTTP headers.

## Check-health and statistics

For reliable monitoring, nginx-auth-ldap provides a simple health-check and some basic statistics.

## Logging

- logs are structured (using logrus), in a text or JSON format
- logs and request logs are clearly separated
- logs can be sent to syslog

# Install

## Prerequisites

- Nginx, compiled with the `ngx_http_auth_request_module` module.
- LDAP server(s)
- Redis is needed for some features (statistics, watching request flow)
- Linux (should work on other UNIX too)
- Only compiles on Go >= 1.8

## Get it

`go get -u github.com/stephane-martin/nginx-auth-ldap`

The dependencies are vendored.

# Configuration

## Configuration sources

### File

**See [the configuration example](https://github.com/stephane-martin/nginx-auth-ldap/blob/master/nginx-auth-ldap.example.toml)**.

The configuration file has to be `nginx-auth-ldap.toml`. It is looked for in `/etc` and
in the directory specified by the commandline flag `--config=XXX`.

### Environment variables

It is also possible to configure nginx-auth-ldap through environment variables.
See the function in [envmapping.go](https://github.com/stephane-martin/nginx-auth-ldap/blob/master/conf/envmapping.go)
for the mappings.

```
NAL_CACHE_EXPIRES="3M" NAL_REALM="My Realm" ... nginx-auth-ldap serve
```

### Consul

The configuration can be stored in the key-value part of Consul. Put the parameters under
the `nginx-auth-ldap/conf/` prefix in Consul KV, and run `nginx-auth-ldap` with
the `--consul` flag.

For example:

```
consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/conf/cache/expires 3m
consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/conf/http/realm 'My Realm'
nginx-auth-ldap serve --consul=http://127.0.0.1:8500
```

## Configuring the LDAP servers

Multiple LDAP directories can be configured, for example one master and some
slaves. In that case the LDAP requests used to authenticate users will be
randomly load-balanced through the directories. Moreover, if one LDAP directory
is not responding, then another will be tried.

Configuring the LDAP directories has two steps :
- configure the defaults parameters that would apply to all directories
- configure the specific paramaters (mostly the `host`) for each directory

### In the configuration file

The default parameters are inside the `[defaultldap]` section. Here you define
the LDAP parameters than you want to share among all the directories.

Each individual LDAP directory must then be defined in an additional `[[ldap]]`
section.

nginx-auth-ldap does not reload automatically when the configuration file is
modified. You need to send a SIGHUP to the process.

### In Consul KV

In Consul KV you define the default LDAP parameters under the prefix `nginx-auth-ldap/conf/defaultldap`.

The individual LDAP servers can be defined under `nginx-auth-ldap/ldap/[ID]/`,
where `[ID]` is a meaningless identifier.

nginx-auth-ldap automatically reloads when the configuration items in Consul KV
are modified.

```
consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/conf/defaultldap/port 389
...

consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/ldap/1/host 127.0.0.1

consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/ldap/2/host 10.1.1.1
consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/ldap/2/port 636
consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/ldap/2/tls_type tls
consul kv put -http-addr=127.0.0.1:8500 nginx-auth-ldap/ldap/2/insecure true
```

### By Consul discovery

If your LDAP servers are registered in Consul as service with health
checks, you don't need to (statically) define the LDAP servers in nginx-auth-ldap
configuration. Instead, just tell nginx-auth-ldap where to find the LDAP
services. nginx-auth-ldap will try the discovery if you provide the
`--ldap-service-name` commandline option. Only LDAP servers that are registered
in Consul with a passing health-check will be discovered.

```
nginx-auth-ldap serve --consul=http://127.0.0.1:8500 --ldap-service-name slapd --ldap-datacenter ldapdc
```

This means: look for services called `slapd`, that's defined in the `ldapdc`
Consul datacenter. The `slapd` hosts and ports, discovered in Consul, completed by
`defaultldap` parameters, will be used as LDAP servers to perform the 
authentication.

It is also possible to filter the discovered LDAP services by a Consul tag with `--ldap-tag`.

To print the currently discovered and visible LDAP servers from Consul:

```
nginx-auth-ldap discovered --consul=http://127.0.0.1:8500 --ldap-service-name slapd --ldap-datacenter ldapdc
```

The discovery is dynamic: LDAP servers will be added/removed to the list when
their Concul health-checks succeed/fail.

## Check configuration

To check nginx-auth-ldap configuration, use the `print-config` command:

```
# Without consul
nginx-auth-ldap print-config

# With consul (merge configuration from file and Consul KV)
nginx-auth-ldap print-config --consul=http://127.0.0.1:8500

# Also print the current discovered LDAP directories:
nginx-auth-ldap print-config --consul=http://127.0.0.1:8500 --discover --ldap-service-name slapd --ldap-datacenter ldapdc
```

# Main commands

## Running

### Launching `nginx-auth-ldap`

`nginx-auth-ldap` listens on two ports: one for the main Auth service, the other
one for the API service. The ports are configurable.

To start listening, use `nginx-auth-ldap serve`.

### Logging

There are two kinds of logs: the 'normal logs', that trace `nginx-auth-ldap`
activity, and the 'request logs', that trace the received requests and their
results.

By default, the normals logs are written to `stderr`, and the request logs to
`stdout`.

If the `--syslog` flag is provided, they will both be sent to the
local syslog daemon. (They use different syslog tags).

To write the normal logs to a file, use `--logfile=XXX`. Similarly use
`--req-logfile=YYY` for the request logs.

Logs are written in text format by default. Use the `--json` flag to write them
as JSON instead.

Log verbosity can be set for the normal logs and the request logs respectively
with the `--loglevel` and `--req-loglevel` flags. Successful authentications
will only be logged in the request logs at level 'DEBUG'.

### Redis and the request logs

If Redis is enabled in configuration, the request logs:

-   will be written to some Redis sorted sets. (We can calculate some metrics from
Redis afterwards).
-   will be erased from Redis after some configurable period.
-   will be published as a Redis PUBSUB. (We can synchronously expose the request
logs this way).

### Registering in Consul

`nginx-auth-ldap` can register itself as a Consul service:
`nginx-auth-ldap serve --consul=XXX --register`.

## Stopping

Send SIGTERM or SIGINT to the `nginx-auth-ldap` process.

## Reload the configuration file

Send SIGHUP to the `nginx-auth-ldap` process.

## Watch the flow of requests

If Redis in enabled, you can watch the request logs as they are generated with
the `monitor` command. For example, try:

```
nginx-auth-ldap serve --req-loglevel=DEBUG
```

Then in another terminal:

```
nginx-auth-ldap monitor --json
```

# HTTP endpoints

## Auth service

The Auth service listens on address/port defined by configuration parameters
`http.bind_addr` and `http.port`.

It provides the following endpoints:

-   `/nginx`: where Nginx should send the authentication subrequests.
-   `/auth`: authentication through HTTP POST: in the incoming request,
    `username` and `password` should be set as HTTP `application/x-www-form-urlencoded`
    parameters. Returns 200, 401, 403... like the /nginx endpoint.
-   `/health`: simple health-check endpoint. Returns 200 if everything looks OK.

## API service

The API service listens on address/port defined by configuration parameters
`api.bind_addr` and `api.port`.

It provides the following endpoints:

-   `/status`: returns 200 and a dummy message if `nginx-auth-ldap` is running
-   `/health`: simple health-check endpoint. Returns 200 if everything looks OK.
-   `/conf`: returns the current configuration
-   `/reload`: POST there to trigger a configuration reload
-   `/stats`: if Redis is enabled, some metrics are returned in a JSON format.
-   `/events`: if Redis is enabled, the request logs are posted there as Server
    Side Events.

# How to get user information in the backend services

The backend services that are protected by nginx-auth-ldap get information
about the authenticated user through the following ways:

-   The `Authorization` HTTP header is passed. Optionaly, the user password
    can be masked in that header if `http.mask_password` is true.
-   The username is passed in the `X-REMOTE-USER` HTTP header.
-   If a RSA private key is defined in `nginx-auth-ldap` configuration, a signed
    JWT token is passed in the `X-REMOTE-JWT` header.

To define a RSA private key, provide the path to a PEM-encoded file in
`signature.private_key_path`, or directly the PEM-encoded key in
`signature.private_key_content`.

(To generate such a private key, you can use `nginx-auth-ldap generate-rsa-keys`.)

# Nginx configuration example

Adapt it to your needs.


```nginx
server {
    location /backend_service_to_protect {
        auth_request /nginx;

        # gather info from nginx-auth-ldap HTTP response headers
        auth_request_set $nalcookie $upstream_http_x_nal_cookie;
        auth_request_set $remote $upstream_http_x_remote_user;
        auth_request_set $auth $upstream_http_authorization;
        auth_request_set $backendjwt $upstream_http_x_remote_jwt;

        # pass info to the backend service
        proxy_set_header REMOTE_USER $remote;
        proxy_set_header REMOTE-USER $remote;
        proxy_set_header X-REMOTE-USER $remote;
        proxy_set_header X-REMOTE-JWT $backendjwt;
        proxy_set_header Authorization $auth;

        # This cookie contains an internal nginx-auth-ldap encrypted token that's
        # used to avoid to bind to the LDAP servers in subsequent requests.
        # The expiration period for that token is defined by `cache.expires`.
        # It is a kind of "authentication caching" mechanism.
        add_header Set-Cookie "NGINX_AUTH_LDAP=$nalcookie;Path=/;HttpOnly";
    }

    location = /nginx {
        internal;
        proxy_pass http://NGINX-AUTH-LDAP-HOST:NGINX-AUTH-LDAP-PORT;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        # pass some information to nginx-auth-ldap about the incoming request
        # (useful for the request logs)
        proxy_set_header X-Forwarded-Server $http_host;
        proxy_set_header X-Forwarded-Host $http_host:443;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Forwarded "for=$remote_addr; proto=https";
        proxy_set_header X-Forwarded-Port 443;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

