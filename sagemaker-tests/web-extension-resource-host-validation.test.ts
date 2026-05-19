import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('fix-web-extension-resource-host-validation.diff validation', () => {
  test('webClientServer.ts should have host validation function', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/server/node/webClientServer.ts');

    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const content = readFileSync(filePath, 'utf8');

    if (!content.includes('function isAllowedExtensionResourceHost(')) {
      throw new Error('Expected isAllowedExtensionResourceHost function not found');
    }

    console.log('PASS: Host validation function found');
  });

  test('webClientServer.ts should validate hosts before proxying', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/server/node/webClientServer.ts');

    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }

    const content = readFileSync(filePath, 'utf8');

    if (!content.includes('_isAllowedWebExtensionResourceHost')) {
      throw new Error('Expected host validation method not found');
    }

    console.log('PASS: Host validation method found');
  });
});
