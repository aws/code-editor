import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('local-storage.diff validation', () => {
  test('webClientServer.ts should pass userDataPath to browser', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/server/node/webClientServer.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedLine = "userDataPath: this._environmentService.userDataPath,";
    
    if (!content.includes(expectedLine)) {
      throw new Error(`Expected userDataPath configuration not found in ${filePath}`);
    }
    
    console.log('PASS: userDataPath configuration found in webClientServer.ts');
  });

  test('web.api.ts should have userDataPath property', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/browser/web.api.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for userDataPath property
    const userDataPathProperty = "readonly userDataPath?: string";
    if (!content.includes(userDataPathProperty)) {
      throw new Error(`Expected userDataPath property not found in ${filePath}`);
    }
    
    console.log('PASS: userDataPath property found in web.api.ts');
  });

  test('environmentService.ts should have userDataPath getter', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/services/environment/browser/environmentService.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for userDataPath getter
    const userDataPathGetter = "get userDataPath(): string {";
    if (!content.includes(userDataPathGetter)) {
      throw new Error(`Expected userDataPath getter not found in ${filePath}`);
    }
    
    // Check for modified userRoamingDataHome
    const userRoamingDataHome = "get userRoamingDataHome(): URI { return joinPath(URI.file(this.userDataPath).with({ scheme: Schemas.vscodeRemote }), 'User'); }";
    if (!content.includes(userRoamingDataHome)) {
      throw new Error(`Expected modified userRoamingDataHome not found in ${filePath}`);
    }
    
    console.log('PASS: Local storage modifications found in environmentService.ts');
  });
});
