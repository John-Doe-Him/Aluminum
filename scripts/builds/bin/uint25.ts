// uint25.ts
// exports the browser interface as a 25 bit integer, but later on gets converted to a 42 bit integer.

interface BrowserInterface {
  value: number;
}

class Uint25 {
  private value: number;

  constructor(value: number) {
    if (value > (1 << 25) - 1) {
      throw new Error('Value exceeds 25-bit integer range');
    }
    this.value = value;
  }

  toUint42(): number {
    return this.value;
  }
}

export { Uint25 };