import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('sagemaker-open-notebook-extension.patch validation', () => {
  test('gulpfile.extensions.js should include sagemaker-open-notebook-extension', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'build/gulpfile.extensions.js');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedEntry = "'extensions/sagemaker-open-notebook-extension/tsconfig.json',";
    
    if (!content.includes(expectedEntry)) {
      throw new Error(`Expected gulpfile entry not found in ${filePath}`);
    }
    
    console.log('PASS: Open notebook extension added to gulpfile.extensions.js');
  });

  test('dirs.js should include sagemaker-open-notebook-extension', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'build/npm/dirs.js');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedEntry = "'extensions/sagemaker-open-notebook-extension',";
    
    if (!content.includes(expectedEntry)) {
      throw new Error(`Expected dirs.js entry not found in ${filePath}`);
    }
    
    console.log('PASS: Open notebook extension added to dirs.js');
  });

  test('sagemaker-open-notebook-extension should have package.json', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-open-notebook-extension/package.json');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const packageJson = JSON.parse(content);
    
    if (packageJson.name !== 'sagemaker-open-notebook-extension') {
      throw new Error(`Expected extension name 'sagemaker-open-notebook-extension', got: ${packageJson.name}`);
    }
    
    console.log('PASS: Open notebook extension package.json is valid');
  });

  test('sagemaker-open-notebook-extension should have main extension file', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-open-notebook-extension/src/extension.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    console.log('PASS: Open notebook extension main file exists');
  });
});
