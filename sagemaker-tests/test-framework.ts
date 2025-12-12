// Simple test framework for Node.js
export function describe(name: string, fn: () => void) {
  console.log(`\n${name}`);
  try {
    fn();
  } catch (error) {
    console.error(`Test suite failed: ${error.message}`);
    process.exit(1);
  }
}

export function test(name: string, fn: () => void) {
  try {
    fn();
    console.log(`   ${name}`);
  } catch (error) {
    console.error(`${name}: ${error.message}`);
    throw error;
  }
}

// Make functions global for test files
(global as any).describe = describe;
(global as any).test = test;
