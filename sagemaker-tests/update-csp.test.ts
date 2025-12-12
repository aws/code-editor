import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('update-csp.diff validation', () => {
  test('webClientServer.ts should have required CSP configuration', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/server/node/webClientServer.ts');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const cspKeywords = [
      'connect-src',
      'https://main.vscode-cdn.net',
      'http://localhost:*',
      'https://localhost:*', 
      'https://login.microsoftonline.com/', 
      'https://update.code.visualstudio.com',
      'https://*.vscode-unpkg.net/', 
      'https://default.exp-tas.com/vscode/ab', 
      'https://vscode-sync.trafficmanager.net', 
      'https://vscode-sync-insiders.trafficmanager.net', 
      'https://*.gallerycdn.vsassets.io', 
      'https://marketplace.visualstudio.com', 
      'https://openvsxorg.blob.core.windows.net', 
      'https://az764295.vo.msecnd.net',  
      'https://code.visualstudio.com', 
      'https://*.gallery.vsassets.io', 
      'https://*.rel.tunnels.api.visualstudio.com',
      'https://*.servicebus.windows.net/', 
      'https://vscode.blob.core.windows.net', 
      'https://vscode.search.windows.net', 
      'https://vsmarketplacebadges.dev', 
      'https://vscode.download.prss.microsoft.com', 
      'https://download.visualstudio.microsoft.com', 
      'https://*.vscode-unpkg.net',
      'https://open-vsx.org'
    ];

    const hasAllKeywords = cspKeywords.every(keyword => content.includes(keyword));
    if (!hasAllKeywords) {
      throw new Error(`Required CSP directive not found in ${filePath}`);
    }
    
    console.log('PASS: Required CSP configuration found in webClientServer.ts');
  });
});
