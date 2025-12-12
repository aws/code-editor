import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('disable-telemetry.diff validation', () => {
  test('telemetryService.ts should have telemetry disabled by default', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/platform/telemetry/common/telemetryService.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check that enum only contains OFF
    const enumLine = "'enum': [TelemetryConfiguration.OFF],";
    if (!content.includes(enumLine)) {
      throw new Error(`Expected telemetry enum restriction not found in ${filePath}`);
    }
    
    // Check that default is OFF
    const defaultLine = "'default': TelemetryConfiguration.OFF,";
    if (!content.includes(defaultLine)) {
      throw new Error(`Expected telemetry default OFF not found in ${filePath}`);
    }
    
    console.log('PASS: Telemetry disabled by default in telemetryService.ts');
  });

  test('desktop.contribution.ts should have crash reporter disabled', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/workbench/electron-sandbox/desktop.contribution.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check crash reporter is disabled
    const crashReporterDisabled = "'default': false,";
    if (!content.includes(crashReporterDisabled)) {
      throw new Error(`Expected crash reporter disabled not found in ${filePath}`);
    }
    
    console.log('PASS: Crash reporter disabled in desktop.contribution.ts');
  });

  test('1dsAppender.ts should have Microsoft endpoints blocked', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/platform/telemetry/common/1dsAppender.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    
    // Check endpoints are redirected to 0.0.0.0
    const blockedEndpoint = "const endpointUrl = 'https://0.0.0.0/OneCollector/1.0';";
    const blockedHealthEndpoint = "const endpointHealthUrl = 'https://0.0.0.0/ping';";
    
    if (!content.includes(blockedEndpoint)) {
      throw new Error(`Expected blocked endpoint not found in ${filePath}`);
    }
    
    if (!content.includes(blockedHealthEndpoint)) {
      throw new Error(`Expected blocked health endpoint not found in ${filePath}`);
    }
    
    console.log('PASS: Microsoft telemetry endpoints blocked in 1dsAppender.ts');
  });
});
