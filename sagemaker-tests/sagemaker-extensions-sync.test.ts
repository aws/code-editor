import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('sagemaker-extensions-sync.patch validation', () => {
  test('gulpfile.extensions.js should include sagemaker-extensions-sync', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'build/gulpfile.extensions.js');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedEntry = "'extensions/sagemaker-extensions-sync/tsconfig.json',";
    
    if (!content.includes(expectedEntry)) {
      throw new Error(`Expected gulpfile entry not found in ${filePath}`);
    }
    
    console.log('PASS: Extensions sync added to gulpfile.extensions.js');
  });

  test('dirs.js should include sagemaker-extensions-sync', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'build/npm/dirs.js');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedEntry = "'extensions/sagemaker-extensions-sync',";
    
    if (!content.includes(expectedEntry)) {
      throw new Error(`Expected dirs.js entry not found in ${filePath}`);
    }
    
    console.log('PASS: Extensions sync added to dirs.js');
  });

  test('sagemaker-extensions-sync should have .vscodeignore', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-extensions-sync/.vscodeignore');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for .vscode ignore pattern
    if (!content.includes('.vscode/**')) {
      throw new Error(`Expected .vscode ignore pattern not found in ${filePath}`);
    }
    
    console.log('PASS: Extensions sync .vscodeignore found');
  });

  test('sagemaker-extensions-sync should have package.json', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-extensions-sync/package.json');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const packageJson = JSON.parse(content);
    
    if (packageJson.name !== 'sagemaker-extensions-sync') {
      throw new Error(`Expected extension name 'sagemaker-extensions-sync', got: ${packageJson.name}`);
    }
    
    console.log('PASS: Extensions sync package.json is valid');
  });
});
