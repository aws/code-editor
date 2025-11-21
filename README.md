## Code Editor

This is the repo for `code-editor`.

## ⚠️ Security Advisory - CVE-2025-13223 and CVE-2025-13224

**Affected Components:** Chromium versions prior to 142.0.7444.175/.176 (Windows), 142.0.7444.176 (Mac), and 142.0.7444.175 (Linux)

**Impact Assessment:**
- Code Editor depends on Code OSS → Electron → Chromium
- Current Electron [v39.2.2](https://github.com/electron/electron/releases/tag/v39.2.2) includes vulnerable Chromium 142.0.7444.162
- **Code Editor web-server builds are NOT affected** - we distribute web-server artifacts that do not include Electron dependencies
- Standalone desktop builds may be affected if built locally

**Mitigation Status:**
- Fix pending Electron's Chromium update
- Web-server distribution remains secure as it excludes Electron components
- Users building standalone desktop versions should monitor for Electron updates

**Technical Details:**
Code OSS uses Electron only for [desktop builds](https://github.com/microsoft/vscode/blob/main/build/gulpfile.vscode.mjs#L71-L75), not for [web-server builds](https://github.com/microsoft/vscode/blob/main/build/gulpfile.reh.mjs#L92-L97). Our distributed artifacts contain no Electron references.

### Repository structure

The repository structure is the following:
- `overrides`: Non-code asset overrides. The file paths here follow the structure of the `third-party-src` submodule, and the files here override the files in `third-party-src` during the build process.
- `package-lock-overrides`: Contains `package-lock.json` files to keep dependencies in sync with patched `package.json` files. These locally generated files ensure `npm ci` works correctly. They override corresponding files in `third-party-src` during build.
- `patches`: Patch files created by [Quilt](https://linux.die.net/man/1/quilt), grouped around features.
- `third-party-src`: Git submodule linking to the upstream [Code-OSS](https://github.com/microsoft/vscode/) commit. The patches are applied on top of this specific commit.

## Creating a new release

See [RELEASE](RELEASE.md) for more information.

## Troubleshooting and Feedback

See [CONTRIBUTING](CONTRIBUTING.md#reporting-bugsfeature-requests) for more information.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT License. See the LICENSE file.
