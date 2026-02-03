import React from "react";

type ModeSelectorProps = {
  productModes: readonly string[];
  modes: readonly string[];
  policies: readonly string[];
  productMode: string;
  mode: string;
  policy: string;
  classicReady?: boolean;
  disabled?: boolean;
  onProductModeChange: (mode: string) => void;
  onModeChange: (mode: string) => void;
  onPolicyChange: (policy: string) => void;
};

export function ModeSelector({
  productModes,
  modes,
  policies,
  productMode,
  mode,
  policy,
  classicReady = true,
  disabled = false,
  onProductModeChange,
  onModeChange,
  onPolicyChange
}: ModeSelectorProps) {
  const modeDisabled =
    disabled ||
    productMode === "GUARANTEED" ||
    (productMode === "CLASSIC" && !classicReady);
  const policyDisabled =
    disabled ||
    productMode === "GUARANTEED" ||
    (productMode === "CLASSIC" && !classicReady);
  return (
    <>
      <h2>Product</h2>
      <div className="mode-row">
        {productModes.map((m) => (
          <div
            key={m}
            className={`mode-pill ${productMode === m ? "active" : ""} ${
              disabled ? "disabled" : ""
            }`}
            onClick={() => {
              if (!disabled) onProductModeChange(m);
            }}
          >
            {m}
          </div>
        ))}
      </div>
      <h2>Mode</h2>
      <div className="mode-row">
        {modes.map((m) => (
          <div
            key={m}
            className={`mode-pill ${mode === m ? "active" : ""} ${
              modeDisabled ? "disabled" : ""
            }`}
            onClick={() => {
              if (!modeDisabled) onModeChange(m);
            }}
          >
            {m}
          </div>
        ))}
      </div>
      <h2 style={{ marginTop: 16 }}>Candidate policy</h2>
      <div className="mode-row">
        {policies.map((p) => (
          <div
            key={p}
            className={`mode-pill ${policy === p ? "active" : ""} ${
              policyDisabled ? "disabled" : ""
            }`}
            onClick={() => {
              if (!policyDisabled) onPolicyChange(p);
            }}
          >
            {p}
          </div>
        ))}
      </div>
    </>
  );
}
