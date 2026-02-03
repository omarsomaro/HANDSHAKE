import React from "react";
import type { LogLine } from "../hooks/useLogs";

type ConsolePanelProps = {
  logs: LogLine[];
  filter: string;
  onFilterChange: (val: string) => void;
  onClear: () => void;
};

export function ConsolePanel({
  logs,
  filter,
  onFilterChange,
  onClear
}: ConsolePanelProps) {
  return (
    <div className="panel">
      <h2>Console</h2>
      <input
        placeholder="filter logs"
        value={filter}
        onChange={(e) => onFilterChange(e.target.value)}
      />
      <div className="console" style={{ marginTop: 12 }}>
        {logs.map((line, idx) => (
          <div key={`${line.ts}-${idx}`} className="console-line">
            <span className="meta">
              [{line.ts}] {line.label}
            </span>
            <span>{line.body}</span>
          </div>
        ))}
        {logs.length === 0 && <div className="console-line">No events</div>}
      </div>
      <div style={{ marginTop: 10 }}>
        <button className="secondary" onClick={onClear}>
          Clear
        </button>
      </div>
    </div>
  );
}
