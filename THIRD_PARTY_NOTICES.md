# Third-party components

The MIT license at the repository root applies to the project's original code.
It does not replace third-party licenses or grant rights to third-party trademarks.

Dependency versions are pinned in Cargo.lock and npm package-lock.json files.
Cargo/npm package distributions include their own license information and notices;
retain the applicable notices when redistributing source or binaries.
Examples include vodozemac, Tauri, React, ZXing, AndroidX, SQLite and Caddy.
The generated Gradle wrapper and scripts are Gradle components under Apache-2.0;
the original copyright headers are retained and LICENSES/Apache-2.0.txt is included.
Caddy is downloaded separately by the deployment packager from its upstream release;
its binary is not included in this repository. Include upstream license notices
when distributing a deployment package containing it.

This source snapshot includes project icons/illustrations. No proprietary fonts,
production signing certificates or prebuilt application binaries are included.
A dependency license inventory can be generated from Cargo metadata, npm lockfiles
and the Android Gradle dependency report for the targets being distributed.
