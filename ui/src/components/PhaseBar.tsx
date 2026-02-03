import React from "react";

export type PhaseState = "done" | "active" | "pending";

type Phase = {
  label: string;
  state: PhaseState;
};

type PhaseBarProps = {
  phases: Phase[];
};

export function PhaseBar({ phases }: PhaseBarProps) {
  return (
    <div className="phase-bar">
      {phases.map((phase) => (
        <div key={phase.label} className={`phase ${phase.state}`}>
          <span className="phase-dot" />
          <span>{phase.label}</span>
        </div>
      ))}
    </div>
  );
}
