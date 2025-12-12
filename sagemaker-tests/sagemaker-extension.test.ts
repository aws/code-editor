import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('sagemaker-extension.diff validation', () => {
  test('sagemaker-extension should have main extension.ts with required imports', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-extension/src/extension.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for SessionWarning import
    const sessionWarningImport = 'import { SessionWarning } from "./sessionWarning";';
    if (!content.includes(sessionWarningImport)) {
      throw new Error(`Expected SessionWarning import not found in ${filePath}`);
    }

    // Check for constants import
    const constantsImport = 'SAGEMAKER_METADATA_PATH,';
    if (!content.includes(constantsImport)) {
      throw new Error(`Expected constants import not found in ${filePath}`);
    }

    // Check for command constants
    const parseCommand = "const PARSE_SAGEMAKER_COOKIE_COMMAND = 'sagemaker.parseCookies';";
    if (!content.includes(parseCommand)) {
      throw new Error(`Expected parse cookie command not found in ${filePath}`);
    }

    // Check for showWarningDialog function
    const warningFunction = 'function showWarningDialog() {';
    if (!content.includes(warningFunction)) {
      throw new Error(`Expected showWarningDialog function not found in ${filePath}`);
    }
    
    console.log('PASS: SageMaker extension main file has required content');
  });

  test('sagemaker-extension should have package.json with correct configuration', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-extension/package.json');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const packageJson = JSON.parse(content);
    
    if (packageJson.name !== 'sagemaker-extension') {
      throw new Error(`Expected extension name 'sagemaker-extension', got: ${packageJson.name}`);
    }
    
    console.log('PASS: SageMaker extension package.json is valid');
  });
});
