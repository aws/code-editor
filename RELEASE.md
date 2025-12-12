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

1. **Determine versions**:
   - **Code Editor version**: Choose tag name based on the commit's branch
     - Tag format: `major.minor.patch` matching the branch the commit belongs to
     - Example: Commit on `1.0` branch → tag `1.0.0`, `1.0.1`, etc.
   - **SageMaker Code Editor version**: Determine the corresponding SageMaker version
     - Example: Code Editor `1.0.1` → SageMaker Code Editor `1.8.0b7`

2. **Create release**:
   - Go to **Actions** → **Create release** → **Run workflow**
   - Select the branch you want to release from (e.g., `1.0`)
   - Enter:
     - **Code Editor version**: `1.0.1` (semantic version x.y.z or x.y.z-rc.N.)
     - **SageMaker Code Editor version**: `1.8.0b7` (any format)
   - Click **Run workflow**
   - The workflow will:
     - Create tag on the current commit
     - Fetch build artifacts for that commit
     - Inject both versions into product.json
     - Create GitHub release with both tarballs

3. **Release notes**: Include code-oss version and Sagemaker Code Editor Version information in the release description

