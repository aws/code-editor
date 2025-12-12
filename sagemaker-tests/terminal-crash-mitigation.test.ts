import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('terminal-crash-mitigation.patch validation', () => {
  test('sagemaker-terminal-crash-mitigation should have .vscodeignore', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-terminal-crash-mitigation/.vscodeignore');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for specific ignore patterns
    const ignorePatterns = ['.vscode/**', 'src/**', 'tsconfig.json'];
    for (const pattern of ignorePatterns) {
      if (!content.includes(pattern)) {
        throw new Error(`Expected ignore pattern '${pattern}' not found in ${filePath}`);
      }
    }
    
    console.log('PASS: Terminal crash mitigation .vscodeignore found');
  });

  test('sagemaker-terminal-crash-mitigation should have webpack config', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-terminal-crash-mitigation/extension-browser.webpack.config.js');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for Amazon copyright
    const copyright = 'Copyright Amazon.com Inc. or its affiliates. All rights reserved.';
    if (!content.includes(copyright)) {
      throw new Error(`Expected Amazon copyright not found in ${filePath}`);
    }
    
    console.log('PASS: Terminal crash mitigation webpack config found');
  });

  test('sagemaker-terminal-crash-mitigation should have package.json', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-terminal-crash-mitigation/package.json');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const packageJson = JSON.parse(content);
    
    if (packageJson.name !== 'sagemaker-terminal-crash-mitigation') {
      throw new Error(`Expected extension name 'sagemaker-terminal-crash-mitigation', got: ${packageJson.name}`);
    }
    
    console.log('PASS: Terminal crash mitigation package.json is valid');
  });
});
