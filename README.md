# Motivation

Nginx does not provide natively LDAP authentication. But it provides a generic
authentication module, that performs HTTP requests to a backend service to check if 
a user is allowed to access the ressource
(see [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)).

`bouncer` provides such a backend.

# Features

## Consul integration

- `bouncer` configuration can be defined in Consul KV
- if your LDAP directories are services registered in Consul, `bouncer` can find them
- `bouncer` can register itself as a Consul service

## LDAP authentication

`bouncer` can authenticate users based on a LDAP directory. Two authentication
schemes are supported: "direct LDAP bind" or "LDAP search and bind".

Multiple LDAP directories can be defined. In that case, `bouncer` will
load-balance the LDAP requests among them.

On the front-end side, the user credentials can be given as "HTTP Basic"
authentication headers, or via a classical form/session cookie.

## Backend services

Your backend services don't have to deal with authentication anymore. Instead
they rely on nginx and `bouncer` to perform the authentication separately.
The services are given information about the current user by HTTP headers.

## Check-health and statistics

For reliable monitoring, `bouncer` provides a simple health-check and some basic statistics.

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

`go get -u github.com/stephane-martin/bouncer`

The dependencies are vendored.

# Configuration

## Configuration sources

### File

**See [the configuration example](https://github.com/stephane-martin/bouncer/blob/master/bouncer.example.toml)**.

The configuration file has to be `bouncer.toml`. It is looked for in `/etc` and
in the directory specified by the commandline flag `--config=XXX`.

### Environment variables

It is also possible to configure `bouncer` through environment variables.
See the function in [envmapping.go](https://github.com/stephane-martin/bouncer/blob/master/conf/envmapping.go)
for the mappings.

```
NAL_CACHE_EXPIRES="3M" NAL_REALM="My Realm" ... bouncer serve
```

### Consul

The configuration can be stored in the key-value part of Consul. Put the parameters under
the `bouncer/conf/` prefix in Consul KV, and run `bouncer` with
the `--consul` flag.

For example:

```
consul kv put -http-addr=127.0.0.1:8500 bouncer/conf/cache/expires 3m
consul kv put -http-addr=127.0.0.1:8500 bouncer/conf/http/realm 'My Realm'
bouncer serve --consul=http://127.0.0.1:8500
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

bouncer does not reload automatically when the configuration file is
modified. You need to send a SIGHUP to the process.

### In Consul KV

In Consul KV you define the default LDAP parameters under the prefix `bouncer/conf/defaultldap`.

The individual LDAP servers can be defined under `bouncer/ldap/[ID]/`,
where `[ID]` is a meaningless identifier.

bouncer automatically reloads when the configuration items in Consul KV
are modified.

```
consul kv put -http-addr=127.0.0.1:8500 bouncer/conf/defaultldap/port 389
...

consul kv put -http-addr=127.0.0.1:8500 bouncer/ldap/1/host 127.0.0.1

consul kv put -http-addr=127.0.0.1:8500 bouncer/ldap/2/host 10.1.1.1
consul kv put -http-addr=127.0.0.1:8500 bouncer/ldap/2/port 636
consul kv put -http-addr=127.0.0.1:8500 bouncer/ldap/2/tls_type tls
consul kv put -http-addr=127.0.0.1:8500 bouncer/ldap/2/insecure true
```

### By Consul discovery

If your LDAP servers are registered in Consul as service with health
checks, you don't need to (statically) define the LDAP servers in bouncer
configuration. Instead, just tell bouncer where to find the LDAP
services. bouncer will try the discovery if you provide the
`--ldap-service-name` commandline option. Only LDAP servers that are registered
in Consul with a passing health-check will be discovered.

```
bouncer serve --consul=http://127.0.0.1:8500 --ldap-service-name slapd --ldap-datacenter ldapdc
```

This means: look for services called `slapd`, that's defined in the `ldapdc`
Consul datacenter. The `slapd` hosts and ports, discovered in Consul, completed by
`defaultldap` parameters, will be used as LDAP servers to perform the 
authentication.

It is also possible to filter the discovered LDAP services by a Consul tag with `--ldap-tag`.

To print the currently discovered and visible LDAP servers from Consul:

```
bouncer discovered --consul=http://127.0.0.1:8500 --ldap-service-name slapd --ldap-datacenter ldapdc
```

The discovery is dynamic: LDAP servers will be added/removed to the list when
their Concul health-checks succeed/fail.

## Check configuration

To check bouncer configuration, use the `print-config` command:

```
# Without consul
bouncer print-config

# With consul (merge configuration from file and Consul KV)
bouncer print-config --consul=http://127.0.0.1:8500

# Also print the current discovered LDAP directories:
bouncer print-config --consul=http://127.0.0.1:8500 --discover --ldap-service-name slapd --ldap-datacenter ldapdc
```

# Main commands

## Running

### Launching `bouncer`

`bouncer` listens on two ports: one for the main Auth service, the other
one for the API service. The ports are configurable.

To start listening, use `bouncer serve`.

### Logging

There are two kinds of logs: the 'normal logs', that trace `bouncer`
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

`bouncer` can register itself as a Consul service:
`bouncer serve --consul=XXX --register`.

## Stopping

Send SIGTERM or SIGINT to the `bouncer` process.

## Reload the configuration file

Send SIGHUP to the `bouncer` process.

## Watch the flow of requests

If Redis in enabled, you can watch the request logs as they are generated with
the `monitor` command. For example, try:

```
bouncer serve --req-loglevel=DEBUG
```

Then in another terminal:

```
bouncer monitor --json
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

-   `/status`: returns 200 and a dummy message if `bouncer` is running
-   `/health`: simple health-check endpoint. Returns 200 if everything looks OK.
-   `/conf`: returns the current configuration
-   `/reload`: POST there to trigger a configuration reload
-   `/stats`: if Redis is enabled, some metrics are returned in a JSON format.
-   `/events`: if Redis is enabled, the request logs are posted there as Server
    Side Events.

# How to get user information in the backend services

The backend services that are protected by bouncer get information
about the authenticated user through the following ways:

-   The `Authorization` HTTP header is passed. Optionaly, the user password
    can be masked in that header if `http.mask_password` is true.
-   The username is passed in the `X-REMOTE-USER` HTTP header.
-   If a RSA private key is defined in `bouncer` configuration, a signed
    JWT token is passed in the `X-REMOTE-JWT` header.

To define a RSA private key, provide the path to a PEM-encoded file in
`signature.private_key_path`, or directly the PEM-encoded key in
`signature.private_key_content`.

(To generate such a private key, you can use `bouncer generate-rsa-keys`.)

# HTTP Basic Authentication: Nginx configuration example

Adapt it to your needs.


```nginx
server {
    location /backend_service_to_protect {
        auth_request /nginx;

        # gather info from HTTP response headers
        auth_request_set $remote $upstream_http_x_remote_user;
        auth_request_set $auth $upstream_http_authorization;
        auth_request_set $backendjwt $upstream_http_x_remote_jwt;

        # pass info to the backend service
        proxy_set_header REMOTE_USER $remote;
        proxy_set_header REMOTE-USER $remote;
        proxy_set_header X-REMOTE-USER $remote;
        proxy_set_header X-REMOTE-JWT $backendjwt;
        proxy_set_header Authorization $auth;

    }

    location = /nginx {
        internal;
        proxy_pass http://BOUNCER_HOST:BOUNCER_PORT;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        # pass some information to bouncer about the incoming request
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

# Cookie-based Authentication: Nginx configuration example

```nginx
server {
    listen 4343 ssl http2;
    server_name myapp.example.org;

    ...

    location / {
        error_page 401 =200 /nal-login-page;
        auth_request /nginx;

        # gather info from HTTP response headers
        auth_request_set $remote $upstream_http_x_remote_user;
        auth_request_set $auth $upstream_http_authorization;
        auth_request_set $backendjwt $upstream_http_x_remote_jwt;

        # pass info to the backend service
        proxy_set_header REMOTE_USER $remote;
        proxy_set_header REMOTE-USER $remote;
        proxy_set_header X-REMOTE-USER $remote;
        proxy_set_header X-REMOTE-JWT $backendjwt;
        proxy_set_header Authorization $auth;
    }

    location /login {
        proxy_pass http://BOUNCER_HOST:BOUNCER_PORT/nal-login-page;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $http_host:443;
        proxy_set_header X-Forwarded-Server $http_host;
        proxy_set_header X-Forwarded-Port 443;
        proxy_set_header Forwarded "for=$remote_addr; proto=https";
        proxy_set_header X-Scheme https;
        proxy_set_header X-Forwarded-Ssl on;
        proxy_set_header X-Url-Scheme https;
        proxy_set_header X-Original-Uri $request_uri;
        proxy_set_header X-Login-Uri $uri;
    }

    location /logout {
        proxy_pass http://BOUNCER_HOST:BOUNCER_PORT/nal-logout-page;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $http_host:443;
        proxy_set_header X-Forwarded-Server $http_host;
        proxy_set_header X-Forwarded-Port 443;
        proxy_set_header Forwarded "for=$remote_addr; proto=https";
        proxy_set_header X-Scheme https;
        proxy_set_header X-Forwarded-Ssl on;
        proxy_set_header X-Url-Scheme https;
        proxy_set_header X-Original-Uri $request_uri;
    }

    location = /nginx {
        internal;
        proxy_pass http://BOUNCER_HOST:BOUNCER_PORT;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
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

