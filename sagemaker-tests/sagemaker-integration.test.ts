import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('sagemaker-integration.diff validation', () => {
  test('client.ts should exist with SagemakerServerClient class', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/browser/client.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for SagemakerServerClient class
    const clientClass = "export class SagemakerServerClient extends Disposable {";
    if (!content.includes(clientClass)) {
      throw new Error(`Expected SagemakerServerClient class not found in ${filePath}`);
    }
    
    // Check for registerSagemakerCommands method call
    const registerCommands = "this.registerSagemakerCommands();";
    if (!content.includes(registerCommands)) {
      throw new Error(`Expected registerSagemakerCommands call not found in ${filePath}`);
    }

    // Check for getCookieValue method
    const getCookieMethod = "private getCookieValue(name: string): string | undefined {";
    if (!content.includes(getCookieMethod)) {
      throw new Error(`Expected getCookieValue method not found in ${filePath}`);
    }
    
    console.log('PASS: SagemakerServerClient integration found in client.ts');
  });

  test('web.main.ts should instantiate SagemakerServerClient', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/browser/web.main.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for SagemakerServerClient import
    const clientImport = "import { SagemakerServerClient } from"

    if (!content.includes(clientImport)) {
      throw new Error(`Expected SagemakerServerClient import not found in ${filePath}`);
    }
    
    // Check for SagemakerServerClient instantiation with register
    const clientInstantiation = "this._register(instantiationService.createInstance(SagemakerServerClient));";
    if (!content.includes(clientInstantiation)) {
      throw new Error(`Expected SagemakerServerClient instantiation not found in ${filePath}`);
    }
    
    console.log('PASS: SagemakerServerClient integration found in web.main.ts');
  });
});
