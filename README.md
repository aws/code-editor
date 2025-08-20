## Code Editor

This is the repo for `code-editor`.

### Repository structure

The repository structure is the following:
- `overrides`: Non-code asset overrides. The file paths here follow the structure of the `third-party-src` submodule, and the files here override the files in `third-party-src` during the build process.
- `package-lock-overrides`: Contains `package-lock.json` files to keep dependencies in sync with patched `package.json` files. These locally generated files ensure `npm ci` works correctly. They override corresponding files in `third-party-src` during build.
- `patches`: Patch files created by [Quilt](https://linux.die.net/man/1/quilt), grouped around features.
- `third-party-src`: Git submodule linking to the upstream [Code-OSS](https://github.com/microsoft/vscode/) commit. The patches are applied on top of this specific commit.

## Creating a new release

A new release will be automatically created when a new tag is published. The following are the steps to publish a new tag
1. Checkout the branch locally on which you need to publish the new tag.
1. Create a new tag locally using the command `git tag -a 2.0.1 commitHash -m "tag message"`
1. Push the tag to GitHub using `git push origin 2.0.1`.
1. This will create a new tag and will automatically start the release workflow for publishing a new release.

## Troubleshooting and Feedback

See [CONTRIBUTING](CONTRIBUTING.md#reporting-bugsfeature-requests) for more information.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT License. See the LICENSE file.

