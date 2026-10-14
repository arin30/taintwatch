import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { SecurityPlayground } from "./SecurityPlayground";

describe("SecurityPlayground", () => {
  it("renders the security playground sections and interactive controls", () => {
    const html = renderToStaticMarkup(<SecurityPlayground onError={() => {}} />);
    expect(html).toContain("Interactive Anti-Evasion &amp; Canonicalization Lab");
    expect(html).toContain("Cryptographic Inter-Agent Taint Tokens");
    expect(html).toContain("Grammar-Bounded Declassification Sandboxes");
    expect(html).toContain("Preset: Zero-Width Spaces");
    expect(html).toContain("Preset: Cyrillic Homoglyphs");
    expect(html).toContain("Analyze &amp; Canonicalize");
    expect(html).toContain("Issue Token");
    expect(html).toContain("Test Declassification");
  });
});
