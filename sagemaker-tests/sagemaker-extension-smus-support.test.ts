import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('sagemaker-extension-smus-support.patch validation', () => {
  test('constant.ts should have SMUS support constants', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/sagemaker-extension/src/constant.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for SMUS service name constant
    const smusServiceName = "export const SMUS_SERVICE_NAME = 'SageMakerUnifiedStudio';";
    if (!content.includes(smusServiceName)) {
      throw new Error(`Expected SMUS service name constant not found in ${filePath}`);
    }

    // Check for service name environment variable
    const serviceNameEnvVar = "export const SERVICE_NAME_ENV_VAR = 'SERVICE_NAME';";
    if (!content.includes(serviceNameEnvVar)) {
      throw new Error(`Expected service name env var constant not found in ${filePath}`);
    }

    // Check for AdditionalMetadata interface extension
    const additionalMetadata = "AdditionalMetadata?: {\n\t\tDataZoneDomainId?: string\n\t\tDataZoneProjectId?: string\n\t\tDataZoneDomainRegion?: string\n\t}";
    if (!content.includes(additionalMetadata)) {
      throw new Error(`Expected AdditionalMetadata interface not found in ${filePath}`);
    }
    
    console.log('PASS: SMUS support constants found in sagemaker-extension constant.ts');
  });
});
