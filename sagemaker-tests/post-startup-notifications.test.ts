import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('post-startup-notifications.patch validation', () => {
  test('post-startup-notifications should have .vscode/extensions.json', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/post-startup-notifications/.vscode/extensions.json');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const cleanContent = content.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    const extensionsJson = JSON.parse(cleanContent);
    
    // Check for recommended extensions
    const expectedRecommendations = ['dbaeumer.vscode-eslint', 'amodio.tsl-problem-matcher', 'ms-vscode.extension-test-runner'];
    for (const recommendation of expectedRecommendations) {
      if (!extensionsJson.recommendations.includes(recommendation)) {
        throw new Error(`Expected recommendation '${recommendation}' not found in ${filePath}`);
      }
    }
    
    console.log('PASS: Post-startup notifications .vscode/extensions.json found');
  });

  test('post-startup-notifications should have .vscode/launch.json', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/post-startup-notifications/.vscode/launch.json');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const cleanContent = content.replace(/^\s*\/\/.*$/gm, '');
    const launchJson = JSON.parse(cleanContent);
    
    // Check for Run Extension configuration
    const runExtensionConfig = launchJson.configurations.find((config: any) => config.name === 'Run Extension');
    if (!runExtensionConfig) {
      throw new Error(`Expected 'Run Extension' configuration not found in ${filePath}`);
    }
    
    if (runExtensionConfig.type !== 'extensionHost') {
      throw new Error(`Expected extensionHost type not found in ${filePath}`);
    }
    
    console.log('PASS: Post-startup notifications .vscode/launch.json found');
  });

  test('post-startup-notifications should have package.json', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'extensions/post-startup-notifications/package.json');
    
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const packageJson = JSON.parse(content);
    
    if (packageJson.name !== 'post-startup-notifications') {
      throw new Error(`Expected extension name 'post-startup-notifications', got: ${packageJson.name}`);
    }
    
    console.log('PASS: Post-startup notifications package.json is valid');
  });
});
