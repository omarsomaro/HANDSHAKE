import React from "react";

type TopBarProps = {
  statusLabel: string;
  universeId: string;
};

export function TopBar({ statusLabel, universeId }: TopBarProps) {
  return (
    <div className="topbar">
      <div className="brand">
        <span>HANDSHAKE</span>
        <span className="universe-id">{universeId || "HS-UNSET"}</span>
      </div>
      <div className="status-pill">
        <span className={`status-dot ${statusLabel.includes("running") ? "ok" : ""}`} />
        <span>{statusLabel}</span>
      </div>
    </div>
  );
}
