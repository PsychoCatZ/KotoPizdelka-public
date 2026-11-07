# Validation scope

This public source snapshot does not include private deployment logs, screenshots,
personal device reports or old verification claims. Current preparation results
are supplied separately in the publication review report.

Re-run the README test/build commands in your own environment. Rust tests use local
fixtures and loopback relays. Native Windows and Android release builds require the
platform toolchains in BUILDING.md. A frontend build is not a native application
build, and unit tests do not replace physical device file-picker/camera checks.

No independent security audit is claimed. This snapshot does not implement multiple
active devices for one account; restored old ratchets are read-only archives.

## Public snapshot preparation

The cleaned source passed 222 Rust library/integration tests (desktop native package
excluded), 26 frontend tests, TypeScript/Vite build, 5 JVM scanner tests, 14 backup
tests and 7 native updater fixture tests. The relay executable compiled for Linux.
The public QR fixture is synthetic and reproducible with:

```sh
node apps/desktop/frontend/tests/generatePublicQrFixture.cjs
```

The original dense-QR failure is retained: ZXing 3.4.1 fails in the initial
orientation and succeeds after rotation. Full Windows/Android application packages
were not rebuilt for this public snapshot. Preparation does not deploy a service.
