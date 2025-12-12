import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('sagemaker-idle-extension.patch validation', () => {
  test('sagemaker-idle-extension should have README with correct description', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-idle-extension/README.md');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedDescription = "The Code Editor Idle Extension tracks user activity and logs the last active timestamp (in UTC) to a local file.";
    
    if (!content.includes(expectedDescription)) {
      throw new Error(`Expected README description not found in ${filePath}`);
    }
    
    console.log('PASS: SageMaker idle extension README found with correct description');
  });

  test('sagemaker-idle-extension should have webpack config', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-idle-extension/extension-browser.webpack.config.js');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const expectedEntry = "entry: {\n        extension: './src/extension.ts'\n    },";
    
    if (!content.includes(expectedEntry)) {
      throw new Error(`Expected webpack entry not found in ${filePath}`);
    }
    
    console.log('PASS: SageMaker idle extension webpack config found');
  });

  test('sagemaker-idle-extension should have package.json with correct name', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-idle-extension/package.json');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const packageJson = JSON.parse(content);
    
    if (packageJson.name !== 'sagemaker-idle-extension') {
      throw new Error(`Expected extension name 'sagemaker-idle-extension', got: ${packageJson.name}`);
    }
    
    console.log('PASS: SageMaker idle extension package.json is valid');
  });
});
