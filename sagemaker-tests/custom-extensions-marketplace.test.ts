import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import './test-framework';

const PATCHED_VSCODE_DIR = join(process.cwd(), 'code-editor-src');

describe('custom-extensions-marketplace.diff validation', () => {
  test('product.ts should have custom extensions gallery logic', () => {
    const filePath = join(PATCHED_VSCODE_DIR, 'src/vs/platform/product/common/product.ts');
    const productPath = join(PATCHED_VSCODE_DIR, 'product.json');
    if (!existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    
    const content = readFileSync(filePath, 'utf8');
    const productContent = readFileSync(productPath, 'utf8');
    // Check for custom extensions gallery environment variable check
    const customGalleryCheck = "if (env['EXTENSIONS_GALLERY']) {";
    if (!content.includes(customGalleryCheck)) {
      throw new Error(`Expected custom extensions gallery check not found in ${filePath}`);
    }
    
    // Check for custom gallery parsing log
    const customGalleryLog = "console.log(`Custom extensions gallery detected. Parsing...`);";
    if (!content.includes(customGalleryLog)) {
      throw new Error(`Expected custom gallery log not found in ${filePath}`);
    }

    // Check for default gallery log - not needed for Code Editor, reference patches/web-server/marketplace.diff and patches/common/integration.diff
    // const defaultGalleryLog = "console.log(`Using default extensions gallery.`);";
    // if (!content.includes(defaultGalleryLog)) {
    //   throw new Error(`Expected default gallery log not found in ${filePath}`);
    // }
    
    // Check for open-vsx gallery configuration
    const openVsxGallery = '"serviceUrl": "https://open-vsx.org/vscode/gallery",';
    if (!productContent.includes(openVsxGallery)) {
      throw new Error(`Expected open-vsx gallery URL not found in ${productPath}`);
    }

    // Check for item URL
    const itemUrl = '"itemUrl": "https://open-vsx.org/vscode/item",';
    if (!productContent.includes(itemUrl)) {
      throw new Error(`Expected open-vsx item URL not found in ${productPath}`);
    }

    // Check for resource URL template
    const resourceUrl = '"resourceUrlTemplate": "https://open-vsx.org/vscode/unpkg/{publisher}/{name}/{version}/{path}",';
    if (!productContent.includes(resourceUrl)) {
      throw new Error(`Expected open-vsx resource URL template not found in ${productPath}`);
    }

    // Check for gallery logging
    const galleryLogging = "console.log(JSON.stringify(product.extensionsGallery, null, 2));";
    if (!content.includes(galleryLogging)) {
      throw new Error(`Expected gallery logging not found in ${filePath}`);
    }
    
    console.log('PASS: Custom extensions marketplace logic found in product.ts');
  });
});
