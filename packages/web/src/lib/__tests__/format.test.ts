import { afterEach, describe, expect, it, vi } from "vitest";
import { durationMs, pct, shortId, timeAgo } from "../format";

describe("pct", () => {
  it("formats a fraction as a one-decimal percentage", () => {
    expect(pct(0)).toBe("0.0%");
    expect(pct(0.5)).toBe("50.0%");
    expect(pct(1)).toBe("100.0%");
    expect(pct(0.1234)).toBe("12.3%");
  });

  it("renders an em dash for null or undefined", () => {
    expect(pct(null)).toBe("—");
    expect(pct(undefined)).toBe("—");
  });
});

describe("durationMs", () => {
  it("uses ms below one second", () => {
    expect(durationMs(0)).toBe("0ms");
    expect(durationMs(999)).toBe("999ms");
  });

  it("uses seconds below one minute", () => {
    expect(durationMs(1000)).toBe("1.0s");
    expect(durationMs(1500)).toBe("1.5s");
    expect(durationMs(59_000)).toBe("59.0s");
  });

  it("uses minutes from one minute upward", () => {
    expect(durationMs(60_000)).toBe("1.0m");
    expect(durationMs(90_000)).toBe("1.5m");
  });
});

describe("shortId", () => {
  it("drops a prefix before the first underscore", () => {
    expect(shortId("run_abcdefghij")).toBe("abcdefgh");
  });

  it("returns the first 8 chars when there is no underscore", () => {
    expect(shortId("plainid12345")).toBe("plainid1");
  });

  it("keeps short ids intact", () => {
    expect(shortId("run_abc")).toBe("abc");
  });
});

describe("timeAgo", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("formats relative times across unit boundaries", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-28T12:00:00Z"));
    const now = Date.now();

    expect(timeAgo(now - 30 * 1000)).toBe("30s ago");
    expect(timeAgo(now - 5 * 60 * 1000)).toBe("5m ago");
    expect(timeAgo(now - 3 * 3600 * 1000)).toBe("3h ago");
    expect(timeAgo(now - 2 * 86400 * 1000)).toBe("2d ago");
  });
});
