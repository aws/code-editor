import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('sagemaker-ui-dark-theme.patch validation', () => {
  test('sagemaker-ui-dark-theme should have README', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-ui-dark-theme/README.md');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedTitle = '# SageMaker UI Dark Theme';
    
    if (!content.includes(expectedTitle)) {
      throw new Error(`Expected README title not found in ${filePath}`);
    }
    
    console.log('PASS: SageMaker UI dark theme README found');
  });

  test('sagemaker-ui-dark-theme should have .vscodeignore', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-ui-dark-theme/.vscodeignore');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for specific ignore patterns
    const ignorePatterns = ['.vscode/**', 'src/**', 'cgmanifest.json'];
    for (const pattern of ignorePatterns) {
      if (!content.includes(pattern)) {
        throw new Error(`Expected ignore pattern '${pattern}' not found in ${filePath}`);
      }
    }
    
    console.log('PASS: UI dark theme .vscodeignore found');
  });

  test('sagemaker-ui-dark-theme should have webpack config', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-ui-dark-theme/extension-browser.webpack.config.js');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for Amazon copyright
    const copyright = 'Copyright Amazon.com Inc. or its affiliates. All rights reserved.';
    if (!content.includes(copyright)) {
      throw new Error(`Expected Amazon copyright not found in ${filePath}`);
    }
    
    console.log('PASS: UI dark theme webpack config found');
  });

  test('sagemaker-ui-dark-theme should have package.json', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-ui-dark-theme/package.json');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const packageJson = JSON.parse(content);
    
    if (packageJson.name !== 'sagemaker-ui-dark-theme') {
      throw new Error(`Expected extension name 'sagemaker-ui-dark-theme', got: ${packageJson.name}`);
    }
    
    console.log('PASS: UI dark theme package.json is valid');
  });
});
