import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { OscalResultsPage } from "@/routes/OscalResultsPage";

describe("OscalResultsPage", () => {
  it("renders the emitted document, signed artifact, and verification checks", () => {
    render(<OscalResultsPage />);

    expect(
      screen.getByRole("heading", { name: /emit.*verify/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/back-matter resources/i)).toBeInTheDocument();
    // The reused signed-artifact card.
    expect(screen.getByText(/verified/i)).toBeInTheDocument();
    // The verification panel surfaces both signature paths.
    expect(
      screen.getByText(/sigstore keyless signature/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/gpg detached signature/i)).toBeInTheDocument();
  });

  it("frames the verification as illustrative (a pre-signed demo artifact)", () => {
    render(<OscalResultsPage />);

    expect(
      screen.getByText(/illustrative verification of a pre-signed demo artifact/i),
    ).toBeInTheDocument();
  });
});
