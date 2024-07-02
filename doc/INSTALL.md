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

## Configuration

pkimetal uses [Viper](https://github.com/spf13/viper) to read configuration settings from environment variables and/or a `config.yaml` file.

For a full list of configuration options and their default values, please consult the [config.go](/config/config.go) source code.

Here is an example `config.yaml` file that demonstrates some of the highlights:

```yaml
server:
  webserverPort: 12345  # Change the webserver port to 12345 (from the default 8080).
linter:
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

Here is an example of passing a pkimetal configuration parameter in an environment variable:

```bash
docker run -p 8080:8080 -e PKIMETAL_LINTER_FTFY_NUMPROCESSES=0 -it pkimetal
```