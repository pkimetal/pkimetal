# FTFY integration

The [ftfy](https://github.com/rspeer/python-ftfy) integration checks certificate Subject distinguished-name values for text that ftfy would repair, such as mojibake caused by character-encoding mix-ups. It checks string-valued Subject attributes only; it does not lint CRLs, OCSP responses, or other certificate fields.

## Installation

The official pkimetal container includes ftfy and its Python runtime. For other installations, ftfy must be importable by `python3`. By default, pkimetal looks for an ftfy installation managed by pipx and uses its site-packages directory.

If ftfy is installed elsewhere, configure `linter.ftfy.pythonDir` to the directory from which the worker's `python3` process can import the `ftfy` package.

## Configuration

FTFY is enabled by default with one worker process. Set `numProcesses` to zero to disable it, or to a larger positive value to run multiple workers.

```yaml
linter:
  ftfy:
    numProcesses: 1
    pythonDir: autodetect
```

The corresponding environment variables are `PKIMETAL_LINTER_FTFY_NUMPROCESSES` and `PKIMETAL_LINTER_FTFY_PYTHONDIR`.

## Findings

FTFY analyzes the concatenated string values in the Subject DN. Printable ASCII Subjects are normally skipped; semicolons are also checked because ftfy's HTML-entity unescaping may repair text containing them.

The integration reports these conditions as errors before calling ftfy:

- Subject attribute values containing invalid UTF-8 bytes.
- Literal Unicode replacement characters (U+FFFD).
- Line separators U+000A, U+000D, U+0085, U+2028, and U+2029. The finding lists the code points present.

The separator characters are replaced with spaces in the text sent to the worker, so they cannot split its line-oriented input protocol. They are still reported based on the original Subject text.

When ftfy changes the input, each detected change is reported as a warning. The finding includes the text ftfy removed or inserted and its UTF-8 bytes in hexadecimal. The worker enables HTML-entity unescaping and uses ftfy's default line-break handling; it does not apply Unicode normalization, alter ligatures or character width, or uncurl quotes.

Worker communication is bounded by the configured `linter.backendTimeout` (30 seconds by default). A worker I/O failure, timeout, or protocol mismatch produces a fatal finding and causes the worker to be restarted.
