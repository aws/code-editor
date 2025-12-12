import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('signature-verification.diff validation', () => {
  test('extensionManagementService.ts should have signature verification disabled', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/platform/extensionManagement/node/extensionManagementService.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check for first @ts-expect-error comment before VerifyExtensionSignatureConfigKey - not required in Code Editor due to patches/common/allow-unused-vars.diff
    // const firstBypassComment = "\t// @ts-expect-error no-unused-variable\n\tVerifyExtensionSignatureConfigKey,";
    // if (!content.includes(firstBypassComment)) {
    //   throw new Error(`Expected first @ts-expect-error comment not found in ${filePath}`);
    // }
    
    // Check for second @ts-expect-error comment before configurationService - not required in Code Editor due to patches/common/allow-unused-vars.diff
    // const secondBypassComment = "\t\t// @ts-expect-error no-unused-variable\n\t\t@IConfigurationService private readonly configurationService: IConfigurationService,";
    // if (!content.includes(secondBypassComment)) {
    //   throw new Error(`Expected second @ts-expect-error comment not found in ${filePath}`);
    // }
    
    // Check for verifySignature = false modification
    const verifySignatureFalse = "\t\t\tverifySignature = false;";
    if (!content.includes(verifySignatureFalse)) {
      throw new Error(`Expected verifySignature = false not found in ${filePath}`);
    }
    
    console.log('PASS: All signature verification modifications found in extensionManagementService.ts');
  });
});
