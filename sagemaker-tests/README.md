# SageMaker Code Editor Unit Tests

This directory contains TypeScript unit tests that validate all patches applied to the VSCode codebase.

## Test Structure

Each patch file in `patches/series` has a corresponding test file:

- `sagemaker-extension.test.ts` - Validates sagemaker-extension.diff patch
- `disable-online-services.test.ts` - Validates disable-online-services.diff patch
- `disable-telemetry.test.ts` - Validates disable-telemetry.diff patch
- `update-csp.test.ts` - Validates update-csp.diff patch
- `webview.test.ts` - Validates webview.diff patch
- `local-storage.test.ts` - Validates local-storage.diff patch
- `sagemaker-integration.test.ts` - Validates sagemaker-integration.diff patch
- `license.test.ts` - Validates license.diff patch
- `base-path-compatibility.test.ts` - Validates base-path-compatibility.diff patch
- `sagemaker-idle-extension.test.ts` - Validates sagemaker-idle-extension.patch
- `terminal-crash-mitigation.test.ts` - Validates terminal-crash-mitigation.patch
- `sagemaker-open-notebook-extension.test.ts` - Validates sagemaker-open-notebook-extension.patch
- `sagemaker-ui-dark-theme.test.ts` - Validates sagemaker-ui-dark-theme.patch
- `sagemaker-ui-post-startup.test.ts` - Validates sagemaker-ui-post-startup.patch
- `sagemaker-extension-smus-support.test.ts` - Validates sagemaker-extension-smus-support.patch
- `post-startup-notifications.test.ts` - Validates post-startup-notifications.patch
- `sagemaker-extensions-sync.test.ts` - Validates sagemaker-extensions-sync.patch
- `custom-extensions-marketplace.test.ts` - Validates custom-extensions-marketplace.diff patch
- `signature-verification.test.ts` - Validates signature-verification.diff patch
- `display-language.test.ts` - Validates display-language.patch

**Total: 20 test files covering all patches in the series**

## Running Tests

### Locally
```bash
./scripts/run-unit-tests.sh
```

### In CI
Tests run automatically on every push via GitHub Actions in `.github/workflows/ci.yml`

## Test Framework

Tests use a simple Node.js-based framework defined in `test-framework.ts` with:
- `describe()` - Test suite grouping
- `test()` - Individual test cases

## What Tests Validate

Tests check that:
1. Patches are properly applied to `patched-vscode/` directory
2. Expected code modifications exist in target files
3. New files/directories are created where needed
4. Configuration changes are present

## Requirements

- Node.js 20+
- TypeScript compiler (npx tsc)
- Patches must be applied (script handles this automatically)
