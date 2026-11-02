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

## Metrics

pkimetal exposes the following Prometheus metrics on its monitoring server, each labelled with `linter_name`:

Metric | Type | Description
--- | --- | ---
`pkimetal_linter_queue_time` | summary | Seconds that a request waited in the linter's queue.
`pkimetal_linter_processing_time` | summary | Seconds that the linter took to process a request.
`pkimetal_linter_stuck_instances` | gauge | Number of the linter's in-process instances that are [stuck](#stuck-in-process-linters). Always 0 for linters that run as worker processes.
