import "@testing-library/jest-dom/vitest";

// jsdom lacks ResizeObserver, which Radix UI primitives (Switch, Slider, …)
// construct on mount. Stub it so component tests that render those primitives
// don't throw. (Added in v0.10.8 Wave 2 for the Explain screen's Switch.)
class ResizeObserverStub {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver =
  globalThis.ResizeObserver ??
  (ResizeObserverStub as unknown as typeof ResizeObserver);
