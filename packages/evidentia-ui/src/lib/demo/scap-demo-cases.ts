// Lightweight labels for the explicit synthetic SCAP examples.
export const SCAP_DEMO_CASES = Object.freeze(
  [
    {
      id: "oval-5.8-undated",
      label: "OVAL 5.8: no completion assertion",
      profile: "oval-5.8-core-results",
    },
    {
      id: "oval-5.8-asserted",
      label: "OVAL 5.8: operator completion",
      profile: "oval-5.8-core-results",
    },
    {
      id: "oval-5.11.2-undated",
      label: "OVAL 5.11.2: no completion assertion",
      profile: "oval-5.11.2-core-results",
    },
    {
      id: "oval-5.11.2-asserted",
      label: "OVAL 5.11.2: operator completion",
      profile: "oval-5.11.2-core-results",
    },
    {
      id: "oval-5.12.3-undated",
      label: "OVAL 5.12.3: no completion assertion",
      profile: "oval-5.12.3-core-results",
    },
    {
      id: "oval-5.12.3-asserted",
      label: "OVAL 5.12.3: operator completion",
      profile: "oval-5.12.3-core-results",
    },
    {
      id: "xccdf-qualified",
      label: "XCCDF: native completion",
      profile: "xccdf-1.2-results",
    },
    {
      id: "xccdf-future",
      label: "XCCDF: future completion",
      profile: "xccdf-1.2-results",
    },
    {
      id: "xccdf-timezone",
      label: "XCCDF: timezone absent",
      profile: "xccdf-1.2-results",
    },
    {
      id: "xccdf-21-rows",
      label: "XCCDF: 21 synthetic outcomes",
      profile: "xccdf-1.2-results",
    },
    {
      id: "xccdf-empty",
      label: "XCCDF: no selected outcome evidence",
      profile: "xccdf-1.2-results",
    },
    {
      id: "xccdf-second-unit",
      label: "XCCDF: second of two assessments",
      profile: "xccdf-1.2-results",
    },
    {
      id: "cadence-qualified",
      label: "Synthetic requested cadence: qualified",
      profile: "xccdf-1.2-results",
    },
    {
      id: "cadence-undated",
      label: "Synthetic requested cadence: undated",
      profile: "oval-5.8-core-results",
    },
    {
      id: "cadence-empty",
      label: "Synthetic requested cadence: empty",
      profile: "xccdf-1.2-results",
    },
    {
      id: "cadence-unevaluated",
      label: "Synthetic requested cadence: no evaluated outcomes",
      profile: "xccdf-1.2-results",
    },
    {
      id: "oval-5.8-native-positions",
      label: "Synthetic OVAL 5.8: exact native positions",
      profile: "oval-5.8-core-results",
    },
    {
      id: "oval-5.11.2-native-positions",
      label: "Synthetic OVAL 5.11.2: exact native positions",
      profile: "oval-5.11.2-core-results",
    },
    {
      id: "oval-5.12.3-native-positions",
      label: "Synthetic OVAL 5.12.3: exact native positions",
      profile: "oval-5.12.3-core-results",
    },
    {
      id: "xccdf-native-times",
      label: "Synthetic XCCDF: native time positions",
      profile: "xccdf-1.2-results",
    },
  ].map((item) => Object.freeze(item)),
);
