# pkimetal: Installation and Configuration

## Installation: Docker (Recommended method)

Option 1: Use a [prebuilt pkimetal container](https://github.com/orgs/pkimetal/packages?repo_name=pkimetal) from the GitHub Packages [Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

Option 2: Clone this repository and build the container yourself:

```bash
git clone https://github.com/pkimetal/pkimetal
docker build -t pkimetal .
```

To run pkimetal from the command-line, do this:

```bash
docker run -p 8080:8080 -it pkimetal
```

## Installation: Manual (Not supported)

Install the runtime dependencies (see [Dockerfile](/Dockerfile) for tips), and build the pkimetal executable by running `make`.

## Architecture

pkimetal runs two HTTP servers:

| Server | Default Port | Purpose |
|---|---|---|
| Web | 8080 | REST API and web interface |
| Monitoring | 8081 | Health probes, Prometheus metrics, and (optional) debug endpoints |

Both servers can alternatively listen on Unix sockets (see `server.webserverPath` and `server.monitoringPath` below).

By default the monitoring server binds to all interfaces. Set `server.monitoringAddress` to restrict it to a specific address (e.g. `127.0.0.1`).

### Debug endpoints

The monitoring server can expose the following debug endpoints:

| Endpoint | Purpose |
|---|---|
| `/debug/build` | Build information |
| `/debug/config` | Effective runtime configuration |
| `/debug/pprof/` | Go [pprof](https://pkg.go.dev/net/http/pprof) profiling handlers |

These endpoints are **disabled by default**. Set `server.enableDebugEndpoints` to `true` to enable them; while disabled they return `404 Not Found`.

## Configuration

pkimetal uses [Viper](https://github.com/spf13/viper) to read configuration settings from environment variables and/or a `config.yaml` file.

Configuration files are searched for in the following locations (from least to most specific):

1. `/config/config.yaml`
2. `./config/config.yaml`
3. `./config.yaml`

For a full list of configuration options and their default values, please consult the [config.go](/config/config.go) source code.

### Environment Variables

Here is an example of passing a pkimetal configuration parameter in an environment variable:

```bash
docker run -p 8080:8080 -e PKIMETAL_LINTER_FTFY_NUMPROCESSES=0 -it pkimetal
```

### Example `config.yaml`

Here is an example `config.yaml` file that demonstrates some of the highlights:

```yaml
server:
  webserverPort: 12345  # Change the webserver port to 12345 (from the default 8080).
  maxRequestBodySize: 20971520  # Accept request bodies up to 20 MiB (default is 10 MiB).
  enableDebugEndpoints: true  # Expose the /debug/* endpoints on the monitoring server (disabled by default).
linter:
  backendTimeout: 60s  # Allow each linter backend up to 60s per request (default is 30s).
  certlint:
    numProcesses: 2  # Run certlint in 2 processes (instead of the default 1).
  ftfy:
    numProcesses: 0  # Disable ftfy.
  pkilint:
    numProcesses: 4  # Run pkilint in 4 processes (instead of the default 1).
    pythonDir: "/root/pkilint"  # Run pkilint from this directory (instead of autodetecting the directory using pipx).
response:
  defaultFormat: text
```
