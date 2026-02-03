import React from "react";

type WizardStepsProps = {
  steps: string[];
  activeIndex: number;
};

export function WizardSteps({ steps, activeIndex }: WizardStepsProps) {
  return (
    <div className="wizard">
      {steps.map((step, idx) => {
        const state =
          idx < activeIndex ? "done" : idx === activeIndex ? "active" : "pending";
        return (
          <div key={step} className={`wizard-step ${state}`}>
            <span className="wizard-bullet">{idx + 1}</span>
            <span>{step}</span>
          </div>
        );
      })}
    </div>
  );
}
