# Shared linter integration settings

This page describes the settings and behaviour that apply to all of pkimetal's linter integrations. For setup requirements and options specific to an individual linter, see that linter's page in this directory.

Each linter runs as one or more *instances*: either a worker process (e.g. the Python and Ruby linters) or a goroutine within the pkimetal process (e.g. the Go linters). Each linter has its own request queue, from which its instances each process one linting request at a time.

## Configuration

These settings live directly under the `linter` key. The values shown are the defaults.

```yaml
linter:
  maxQueueSize: 8192
  backendTimeout: 30s
  maxIntegerBits: 16384
```

Setting | Environment variable | Description
--- | --- | ---
`maxQueueSize` | `PKIMETAL_LINTER_MAXQUEUESIZE` | Capacity of each linter's request queue.
`backendTimeout` | `PKIMETAL_LINTER_BACKENDTIMEOUT` | Time allowed for a worker process to handle one request.
`maxIntegerBits` | `PKIMETAL_LINTER_MAXINTEGERBITS` | Largest ASN.1 INTEGER accepted in an input, in bits. `0` disables the check.

The overall time limit for a linting request is set separately, by `server.requestTimeout` (30 seconds by default). See the [REST API documentation](../REST_API.md).

### `maxQueueSize`

Each linter that is enabled and applicable to the input receives a copy of every linting request on its own queue. When a linter's queue is full, the request waits for space. If the request is not completed within `server.requestTimeout`, the client receives an HTTP 503 response.

A request that is still queued when its deadline passes is discarded without being linted, so a backlog cannot cause stale work to be processed.

### `backendTimeout`

`backendTimeout` bounds each exchange with a worker process: sending a request to the worker's STDIN and reading its results from STDOUT. The timer starts when an instance begins processing the request, so time spent queued does not count against it. Worker start-up and warm-up are also excluded: a worker that signals readiness is not sent requests until it is ready, however long initialisation takes.

`backendTimeout` does not limit linters that run as goroutines within the pkimetal process, except for any parts of them that communicate with a worker process (e.g. [FTFY](ftfy.md)); for those linters, it is instead the threshold beyond which an instance is reported as [stuck](#stuck-in-process-linters).

If a worker crashes, times out, or produces output that does not follow the response protocol, pkimetal reports a fatal finding for that request (see [Findings](#findings)), then kills and restarts the worker so that subsequent requests are unaffected. A worker that keeps running correctly is not restarted merely because the client stopped waiting; its remaining output is read and discarded instead.

#### Stuck in-process linters

A linter that runs as a goroutine within the pkimetal process cannot be interrupted or killed, so pkimetal does not time it out or start a replacement; doing so could let hung goroutines accumulate without bound. Instead, an in-process linter instance that has been processing one request for longer than `backendTimeout` is reported as *stuck*:

- pkimetal logs an error naming the linter and instance (and a warning if the instance later finishes its request);
- the `pkimetal_linter_stuck_instances` metric counts the linter's stuck instances (see [Metrics](#metrics));
- `/livez` on the monitoring server returns HTTP 503, so that an orchestrator such as Kubernetes can restart pkimetal, which is the only way to reclaim a stuck goroutine.

Whilst all of a linter's instances are stuck, requests to which that linter applies cannot complete and will time out with HTTP 503.

### `maxIntegerBits`

Several linters perform arithmetic whose cost grows steeply (in some cases cubically) with the size of public-key integers, so a single input containing, say, a huge RSA modulus could tie up a linter for a long time. Nothing in the Web PKI needs an integer larger than 16,384 bits.

Before any linter sees an input, pkimetal scans it for ASN.1 INTEGERs larger than `maxIntegerBits`. The scan:

- applies to every POST endpoint (certificates, CRLs, and OCSP responses, signed or to-be-signed);
- includes the contents of BIT STRINGs and OCTET STRINGs that parse completely as ASN.1, so it covers, for example, an RSA or DSA public key, explicit elliptic curve parameters, and certificates embedded in an OCSP response;
- tolerates BER encodings (such as indefinite and non-minimal lengths), so that encoding quirks cannot hide an oversized integer from the check.

If an oversized INTEGER is found, no linting is performed. The response is HTTP 200 and contains a single fatal finding from pkimetal, e.g. `Input contains a 20000-bit INTEGER, which exceeds the 16384-bit limit`.

The scan's cost is linear in the input size: typically under a microsecond for a certificate, and around 14 milliseconds for a pathological 10 MiB input.

## Findings

pkimetal adds findings of its own, under the linter name `pkimetal` or the relevant linter's name:

Linter | Severity | Finding | When
--- | --- | --- | ---
`pkimetal` | meta | `Profile: <profile>; Version: <version>` | Every successful request.
*linter* | meta | `<linter>: Not used [Available:<bool>, Applicable:<bool>]` | The linter is disabled, or does not support the selected profile.
*linter* | meta | `Queued: <duration>; Runtime: <duration>; Version: <version>` | Every request that the linter processed.
`pkimetal` | fatal | `<linter>: linting backend timed out` | A worker exceeded `backendTimeout`.
`pkimetal` | fatal | `<linter>: <error>` | A worker crashed, produced malformed output, or produced an output line larger than 16 MiB. An oversized line does not cause a restart, because the worker remains in sync.
*linter* | fatal | `Recovered from panic: <details>` | A linter running within the pkimetal process panicked.
`pkimetal` | fatal | *description of the problem* | The request was invalid, or contained an oversized INTEGER (see [`maxIntegerBits`](#maxintegerbits)).

Linter workers that encounter an unexpected error whilst linting an input report it as a fatal finding (e.g. `F: Exception: ...`) from that linter and continue serving subsequent requests.

## Severity levels

The severity values are ordered from least to most severe: `meta`, `debug`, `info`, `notice`, `warning`, `error`, `bug`, `fatal`. pkimetal sorts findings in descending order of severity and applies the requested minimum severity inclusively. For example, `severity=error` includes `error`, `bug`, and `fatal` findings. The default minimum is `meta`, which includes all findings.

The values are a ranking used for filtering, not a fully normalized measure of risk across different linter engines. Their usual roles and important variations are:

Severity | Typical use | Important variation
--- | --- | ---
`meta` | pkimetal's profile, linter availability, timing, and version information; not a diagnostic finding | Reserved for pkimetal's own metadata and cannot be returned by a remote linter.
`debug` | Detailed diagnostic information | Some integrations or endpoints may emit it; it is normally useful only when explicitly requested.
`info` | Informational result or an affirmative check with no issue found | Examples include a key not found to be weak, or a check skipped because there was nothing to inspect.
`notice` | A noteworthy condition that is not necessarily a lint failure | Pwnedkeys and remote-linter timeouts default to this level; it can also mean a check had limited coverage.
`warning` | A possible issue, unsupported case, or suggested correction | Examples include unsupported key types and text that a normalizer would change. A violation of an applicable normative `SHOULD`/`SHOULD NOT` requirement is commonly reported at this level.
`error` | A substantive lint finding | Many integrations use it for violations. A violation of an applicable normative `MUST`/`MUST NOT` requirement is commonly reported at this level.
`bug` | More severe than `error` in pkimetal's ordering | Some upstream tools use it for their own findings. Pwnedkeys and remote linters use it by default for API/request errors.
`fatal` | The most severe level; often means the check could not be completed reliably | pkimetal uses it for worker failures, malformed worker output, panics, and invalid input, but an upstream linter can also use it for its own finding. It does not mean the pkimetal process has terminated.

The `SHOULD`/`MUST` mapping is a convention, not a rule enforced by pkimetal. It applies when those capitalized terms are used normatively (as defined by RFC 2119 and RFC 8174), and the requirement applies to the selected profile and artifact. Individual linter engines may map requirements differently or account for permitted exceptions. A `MUST` violation is ordinarily an `error`, not `fatal`; `fatal` is generally for a check or its backend failing.

Integrations do not all assign these levels in the same way:

Integration | How it assigns severity
--- | ---
`badkeys` | `info` for a key reported as OK, `warning` for unsupported or missing keys, `error` for a detected vulnerability, and `fatal` for unparseable input or an exception.
`certlint` | Translates the levels emitted by its upstream tool using the shared worker-output format. Worker exceptions are reported as `fatal`.
`ctlint` | Translates upstream `info`, `notice`, `warning`, `error`, `bug`, and `fatal` levels; certificate parse failures are `fatal`.
`dwklint` | Uses `info` for a non-weak key, `notice` or `warning` when coverage is limited, `error` for a weak key, and `fatal` for parse or check failures.
`ftfy` | Reports invalid text as `error`, proposed text changes as `warning`, and skipped checks as `info`; worker or protocol failures are `fatal`.
`paranoid` | Maps lower-level checks to `warning` and higher-level checks to `error`; unsupported checks are `notice`, while an unchecked signature is `info`.
`pkilint` | Carries severity values from pkilint's JSON output through to pkimetal; an unknown, missing, or `meta` severity is treated as malformed worker output rather than silently becoming metadata.
`pwnedkeys` | Uses `info` when a key is not found to be pwned and `error` when it is. API errors default to `bug`; rate limits and timeouts default to `notice`. These defaults are configurable.
`remote` | Preserves a remote endpoint's finding severity except `meta`, which is reserved. Connection, status, and invalid-response failures use configurable `errorSeverity` (default `bug`, matching pwnedkeys); endpoint timeouts use configurable `timeoutSeverity` (default `notice`).
`rocacheck` | Uses `info` when no ROCA weakness is found and `error` when one is found.
`section7` | Maps rule findings to `info`, `warning`, or `error`, and uses `fatal` when the certificate cannot be parsed.
`x509lint` | Maps upstream `info`, `warning`, and `error`; malformed output is reported as `fatal`.
`zlint` | Maps upstream `notice`, `warning`, `error`, and `fatal`; it does not use `debug`, `info`, or `bug` for its lint results.

There are two notable differences in failure handling. First, pkimetal reports worker crashes, timeouts, protocol errors, and in-process panics as `fatal`; network-backed integrations instead return configurable findings, as described above for pwnedkeys and remote. Second, `bug` is above `error`, but it can describe an API failure as well as an upstream linter result. Do not assume the same severity always means the same condition across integrations; configure the remote integration's failure severities to match your policy.

## Metrics

pkimetal exposes the following Prometheus metrics on its monitoring server. Labels are noted in the descriptions.

Metric | Type | Description
--- | --- | ---
`pkimetal_linter_queue_time` | summary | Seconds that a request waited in the linter's queue.
`pkimetal_linter_processing_time` | summary | Seconds that the linter took to process a request.
`pkimetal_linter_stuck_instances` | gauge | Number of the linter's in-process instances that are [stuck](#stuck-in-process-linters). Always 0 for linters that run as worker processes.
`pkimetal_linter_remote_request_failures_total` | counter | Failed requests to [remote linters](./remote.md), labelled by `linter_name` and `reason`.
