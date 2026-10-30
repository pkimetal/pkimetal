# Section7 CPS Profiles

The section7 backend runs in the pkimetal process and checks certificates and precertificates against your CPS profiles. It does not support CRLs or OCSP responses. No section7 executable or separate runtime is needed.

Set `linter.section7.numGoroutines` to a positive integer and `linter.section7.profilesDir` to a directory containing section7 `.yaml` or `.yml` profiles. The defaults are `0` (disabled) and an empty directory setting. The corresponding environment variables are `PKIMETAL_LINTER_SECTION7_NUMGOROUTINES` and `PKIMETAL_LINTER_SECTION7_PROFILESDIR`.

Use your own CPS profiles in production. Section7 provides [example profiles](https://github.com/cps-kit/section7/tree/v0.1.0/profiles/example) under `profiles/example/` in its repository. Profile discovery is not recursive: when trying those examples, point `profilesDir` at `profiles/example/`, not its parent `profiles/` directory.

For example, mount your profile directory read-only into a container:

```bash
docker run -p 8080:8080 \
  --mount type=bind,src=/absolute/path/to/profiles,dst=/config/profiles,readonly \
  -e PKIMETAL_LINTER_SECTION7_NUMGOROUTINES=1 \
  -e PKIMETAL_LINTER_SECTION7_PROFILESDIR=/config/profiles \
  pkimetal
```

The profile set is loaded and validated once at startup, then shared by all section7 worker goroutines without rereading profile files for each certificate. Files beginning with `_` are shared definitions, not independently selected profiles; section7 resolves their `extends` references. If the backend is enabled, a missing or empty directory, an unreadable profile, or an invalid profile prevents startup. Restart pkimetal after changing profiles.

Profile selection is independent of pkimetal's request profile. Section7 applies at most one profile: among profiles whose `profile.recognized_by.policy_oid` is present in the certificate, it chooses the latest `profile.version` timestamp no later than the certificate's `notBefore`. Unversioned profiles are eligible regardless of issuance time but lose to any eligible versioned profile. If multiple profiles tie for the latest eligible version (including multiple unversioned matches), none is applied and `PROFILE-AMBIGUOUS` is reported. No matching policy produces `PROFILE-NOMATCH`; matching profiles that are all too new produce `PROFILE-TOONEW`.

Findings include the selected profile's file path in `field`, section7's rule ID in `code`, and its original message and severity. The `field` is empty when no profile can be selected.
