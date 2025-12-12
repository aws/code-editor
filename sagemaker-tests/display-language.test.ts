import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('display-language.diff validation', () => {
  test('remoteLanguagePacks.ts should have locale functions', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/server/node/remoteLanguagePacks.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    if (!content.includes('export const getLocaleFromConfig') || 
        !content.includes('export async function getBrowserNLSConfiguration')) {
      throw new Error(`Failed to find locale functions in ${filePath}`);
    }
    
    console.log('PASS: Locale functions found in remoteLanguagePacks.ts');
  });

  test('webClientServer.ts should use locale from args', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/server/node/webClientServer.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    if (!content.includes('this._environmentService.args.locale')) {
      throw new Error(`Failed to find locale from args in ${filePath}`);
    }
    
    console.log('PASS: Locale from args found in webClientServer.ts');
  });

  test('serverEnvironmentService.ts should have locale option', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/server/node/serverEnvironmentService.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    if (!content.includes("'locale': { type: 'string' }")) {
      throw new Error(`Failed to find locale option in ${filePath}`);
    }
    
    console.log('PASS: Locale option found in serverEnvironmentService.ts');
  });

  test('languagePacks.ts should use remote service', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/platform/languagePacks/browser/languagePacks.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    if (!content.includes('ProxyChannel.toService<ILanguagePackService>')) {
      throw new Error(`Failed to find ProxyChannel usage in ${filePath}`);
    }
    
    console.log('PASS: Remote language pack service found in languagePacks.ts');
  });
});
