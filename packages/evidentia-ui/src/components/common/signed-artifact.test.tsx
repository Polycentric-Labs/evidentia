import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import {
  SignedArtifactCard,
  VerificationPanel,
} from "@/components/common/signed-artifact";

const ARTIFACT = {
  filename: "demo.oscal.json",
  framework: "fda-524b-appendix1",
  sha256: "9f2c41e8a7b30d6c5e1f8a92b4d07c3e6a1b9d8f2c4e70a5b3d6f1c8e9a2b7d40",
  runId: "01JZ8K6T7QF3WYB9N2C4D5E6F7",
  signedAt: "2026-04-19T10:47:33Z",
  signer: "demo-signing-identity (test key)",
  rekorLogIndex: "148203394",
  verified: true,
};

describe("SignedArtifactCard", () => {
  it("renders the artifact identity, run id, and verified badge", () => {
    render(<SignedArtifactCard {...ARTIFACT} />);

    expect(screen.getByText("demo.oscal.json")).toBeInTheDocument();
    expect(screen.getByText(ARTIFACT.runId)).toBeInTheDocument();
    expect(screen.getByText(/verified/i)).toBeInTheDocument();
  });

  it("middle-truncates the digest for display but keeps the full value as a title", () => {
    render(<SignedArtifactCard {...ARTIFACT} />);

    const digest = screen.getByText(
      (t) => t.startsWith("9f2c41e8a7b30d") && t.endsWith("7d40"),
    );
    expect(digest).toBeInTheDocument();
    // The visible value is shortened (an ellipsis sits in the middle)...
    expect(digest.textContent).toContain("…");
    // ...while the full digest stays available as the title attribute.
    expect(digest).toHaveAttribute("title", ARTIFACT.sha256);
  });

  it("omits the verified badge when verified is false", () => {
    render(<SignedArtifactCard {...ARTIFACT} verified={false} />);
    expect(screen.queryByText(/verified/i)).not.toBeInTheDocument();
  });
});

describe("VerificationPanel", () => {
  it("renders each verification check with its label and detail", () => {
    render(
      <VerificationPanel
        checks={[
          {
            id: "digest",
            label: "Document digest (SHA-256)",
            status: "verified",
            detail: "Recomputed over the canonical OSCAL JSON.",
          },
          {
            id: "gpg",
            label: "GPG detached signature",
            status: "not-applicable",
            detail: "This artifact uses the Sigstore keyless path.",
          },
        ]}
      />,
    );

    expect(screen.getByText("Document digest (SHA-256)")).toBeInTheDocument();
    expect(
      screen.getByText("Recomputed over the canonical OSCAL JSON."),
    ).toBeInTheDocument();
    expect(screen.getByText("GPG detached signature")).toBeInTheDocument();
    expect(
      screen.getByText("This artifact uses the Sigstore keyless path."),
    ).toBeInTheDocument();
  });
});
