import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('sagemaker-ui-post-startup.patch validation', () => {
  test('webClientServer.ts should have post-startup imports and constants', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/server/node/webClientServer.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for spawn import
    const spawnImport = "import { spawn } from 'child_process';";
    if (!content.includes(spawnImport)) {
      throw new Error(`Expected spawn import not found in ${filePath}`);
    }

    // Check for fs import
    const fsImport = "import * as fs from 'fs';";
    if (!content.includes(fsImport)) {
      throw new Error(`Expected fs import not found in ${filePath}`);
    }

    // Check for ServiceName enum
    const serviceNameEnum = "const enum ServiceName {\n\tSAGEMAKER_UNIFIED_STUDIO = 'SageMakerUnifiedStudio',\n}";
    if (!content.includes(serviceNameEnum)) {
      throw new Error(`Expected ServiceName enum not found in ${filePath}`);
    }

    // Check for POST_STARTUP_SCRIPT_PATH constant
    const postStartupPath = "const POST_STARTUP_SCRIPT_PATH = `/api/poststartup`;";
    if (!content.includes(postStartupPath)) {
      throw new Error(`Expected POST_STARTUP_SCRIPT_PATH constant not found in ${filePath}`);
    }
    
    console.log('PASS: Post-startup modifications found in webClientServer.ts');
  });

  test('gettingStarted.ts should exist and may contain UI modifications', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/contrib/welcomeGettingStarted/browser/gettingStarted.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    console.log('PASS: gettingStarted.ts file exists');
  });

  test('gettingStartedContent.ts should exist and may contain content modifications', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/contrib/welcomeGettingStarted/common/gettingStartedContent.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    console.log('PASS: gettingStartedContent.ts file exists');
  });
});
