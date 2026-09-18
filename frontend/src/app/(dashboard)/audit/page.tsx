"use client";

import { AuditTable } from "@/components/audit/AuditTable";
import { ExportButton } from "@/components/audit/ExportButton";
import { Panel } from "@/components/ui/Panel";

export default function AuditPage() {
  return (
    <div className="flex flex-col gap-14">
      <div className="flex flex-wrap items-center justify-between gap-14">
        <h1 className="m-0 text-5xl font-bold tracking-tight">Audit Log</h1>
        <ExportButton />
      </div>
      <Panel tilt={false} glow="rgba(123,63,242,0.25)">
        <AuditTable />
      </Panel>
    </div>
  );
}
