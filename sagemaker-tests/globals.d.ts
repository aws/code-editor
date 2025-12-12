declare global {
  function describe(name: string, fn: () => void): void;
  function test(name: string, fn: () => void): void;
}

export {};
