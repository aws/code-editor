## Create new release

### Branching Strategy

We use major.minor branches (e.g., `1.0`, `1.1`, `2.1`) for releases.

### Versioning Rules

- **New major version of code-oss** → New major version for our package
  - Example: code-oss 1.x.x → branch `1.0` → tag `1.0.0`, code-oss 2.x.x → branch `2.0` → tag `2.0.0`
- **New version of code-oss** → New major.minor.0 version for our package
  - Example: code-oss 1.85.0 → branch `1.1` → tag `1.1.0`, code-oss 1.86.0 → branch `1.2` → tag `1.2.0`
- **Patch releases** → Increment patch number on existing major.minor branch
  - Example: Bug fixes on branch `1.1` → tags `1.1.1`, `1.1.2`, etc.

### Release Process

1. **Determine Code Editor Version**: Choose tag name based on the commit's branch
   - Tag format: `major.minor.patch` matching the branch the commit belongs to
   - Example: Commit on `1.0` branch → tag `1.0.0`, `1.0.1`, etc.
   - Pre-release candidates have a tag suffix as `rc.{release_candidate_version}`. For example `1.0.4-rc.1` or `1.0.4-rc.2`.

2. **Determine SageMaker Code Editor Version**: 
   - Get in touch with the SageMaker team to decide what SageMaker version needs to be used for the latest release.
   - Hard-code that version in the patch `patches/sagemaker/display-both-versions-in-about.diff` in `product.json`.


3. **Create release**:
   - **Command line**: Push tag to trigger release workflow
     ```bash
     git tag 1.0.0
     git push origin 1.0.0
     ```
   - The workflow will:
     - Fetch build artifacts for that commit
     - Inject Code Editor version from the release tag into product.json
     - Create GitHub release

4. **Release notes**: Include code-oss version and Sagemaker Code Editor Version information in the release description. Release description can be edited once the release workflow creates the release. 