import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('license.diff validation', () => {
  test('LICENSE file should exist with Amazon copyright', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'LICENSE');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for MIT License
    if (!content.includes('MIT License')) {
      throw new Error(`Expected MIT License header not found in ${filePath}`);
    }
    
    // Check for Amazon copyright
    const amazonCopyright = "Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.";
    if (!content.includes(amazonCopyright)) {
      throw new Error(`Expected Amazon copyright not found in ${filePath}`);
    }
    
    console.log('PASS: Amazon MIT License found in LICENSE file');
  });

  test('LICENSE-THIRD-PARTY file should exist', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'LICENSE-THIRD-PARTY');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    console.log('PASS: Third-party license file exists');
  });
});
