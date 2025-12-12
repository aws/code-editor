import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('webview.diff validation', () => {
  test('environmentService.ts should have webview endpoint modification', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/services/environment/browser/environmentService.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedLine = 'const endpoint = (this.options.webviewEndpoint && new URL(this.options.webviewEndpoint, window.location.toString()).toString())';
    
    if (!content.includes(expectedLine)) {
      throw new Error(`Expected webview endpoint modification not found in ${filePath}`);
    }
    
    console.log('PASS: webview endpoint modification found in environmentService.ts');
  });

  test('webClientServer.ts should have webviewEndpoint configuration', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/server/node/webClientServer.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedLine = "webviewEndpoint: staticRoute + '/out/vs/workbench/contrib/webview/browser/pre',";
    
    if (!content.includes(expectedLine)) {
      throw new Error(`Expected webviewEndpoint configuration not found in ${filePath}`);
    }
    
    console.log('PASS: webviewEndpoint configuration found in webClientServer.ts');
  });

  test('webview pre/index.html should have updated CSP hash', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/contrib/webview/browser/pre/index.html');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedHash = "script-src 'sha256-Oi71Tq4Buohx0KDH3yEbVJUzABnqYv9iVLo420HZXqI=' 'self'";
    
    if (!content.includes(expectedHash)) {
      throw new Error(`Expected CSP hash not found in ${filePath}`);
    }
    
    console.log('PASS: Updated CSP hash found in webview pre/index.html');
  });

  test('webview pre/index.html should have hostname bypass logic', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/contrib/webview/browser/pre/index.html');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedLogic = 'if (parent.hostname === hostname) {\n\t\t\t\t\treturn start(parentOrigin)\n\t\t\t\t}';
    
    if (!content.includes(expectedLogic)) {
      throw new Error(`Expected hostname bypass logic not found in ${filePath}`);
    }
    
    console.log('PASS: Hostname bypass logic found in webview pre/index.html');
  });

  test('webWorkerExtensionHostIframe.html should have updated CSP hash', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/services/extensions/worker/webWorkerExtensionHostIframe.html');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedHash = "script-src 'self' 'wasm-unsafe-eval' 'sha256-yhZXuB8LS6t73dvNg6rtLX8y4PHLnqRm5+6DdOGkOcw=' https: http://localhost:* blob:;";
    
    if (!content.includes(expectedHash)) {
      throw new Error(`Expected CSP hash not found in ${filePath}`);
    }
    
    console.log('PASS: Updated CSP hash found in webWorkerExtensionHostIframe.html');
  });

  test('webWorkerExtensionHostIframe.html should have hostname bypass logic', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/services/extensions/worker/webWorkerExtensionHostIframe.html');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedLogic = 'if (parent.hostname === hostname) {\n\t\t\treturn start()\n\t\t}';
    
    if (!content.includes(expectedLogic)) {
      throw new Error(`Expected hostname bypass logic not found in ${filePath}`);
    }
    
    console.log('PASS: Hostname bypass logic found in webWorkerExtensionHostIframe.html');
  });
});
