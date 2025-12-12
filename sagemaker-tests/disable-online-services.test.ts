import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('disable-online-services.diff validation', () => {
  test('update.config.contribution.ts should disable automatic updates', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/platform/update/common/update.config.contribution.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check update mode is set to none
    const updateModeDefault = "default: 'none',";
    if (!content.includes(updateModeDefault)) {
      throw new Error(`Expected update mode 'none' not found in ${filePath}`);
    }
    
    // Check release notes are disabled
    const releaseNotesDefault = "default: false,";
    if (!content.includes(releaseNotesDefault)) {
      throw new Error(`Expected release notes disabled not found in ${filePath}`);
    }
    
    console.log('PASS: Online services disabled in update configuration');
  });
});
