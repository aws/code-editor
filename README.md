## Code Editor

This is the repo for `code-editor`.

### Repository structure

The repository structure is the following:
- `overrides`: Non-code asset overrides. The file paths here follow the structure of the `third-party-src` submodule, and the files here override the files in `third-party-src` during the build process.
- `package-lock-overrides`: Contains `package-lock.json` files to keep dependencies in sync with patched `package.json` files. These locally generated files ensure `npm ci` works correctly. They override corresponding files in `third-party-src` during build.
- `patches`: Patch files created by [Quilt](https://linux.die.net/man/1/quilt), grouped around features.
- `third-party-src`: Git submodule linking to the upstream [Code-OSS](https://github.com/microsoft/vscode/) commit. The patches are applied on top of this specific commit.

## Creating a new release

See [RELEASE](RELEASE.md) for more information.

## Version Information

The following table provides the mapping between Code Editor releases and their corresponding [Code-OSS](https://github.com/microsoft/vscode/) base versions:

| Code Editor Version | Code-OSS Base Version |
|---------------------|-----------------------|
| 1.0.x               | 1.101.2               |


## Troubleshooting and Feedback

See [CONTRIBUTING](CONTRIBUTING.md#reporting-bugsfeature-requests) for more information.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT License. See the LICENSE file.
