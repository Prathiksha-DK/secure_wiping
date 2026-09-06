"use client";

import { Lock } from "lucide-react";
import { Badge } from "@/components/ui/badge";

export interface HunterActiveCase {
  case_id: string;
  device_id?: string;
  device_model?: string;
  image_path?: string;
  image_filename?: string;
  sha256?: string;
  case_status?: string;
}

/**
 * Persistent case-context banner shown to a Hunter operating on an active
 * case, so the case's forensic image can never be confused with a local
 * device. Renders nothing for any other role / when there is no active case.
 */
export default function HunterCaseBanner({ activeCase }: { activeCase: HunterActiveCase | null }) {
  if (!activeCase) return null;

  return (
    <div className="mb-4 p-3.5 rounded-xl border border-emerald-500/40 bg-emerald-950/20 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5">
        <div className="flex items-center gap-1.5">
          <Lock className="h-3.5 w-3.5 text-emerald-400" />
          <span className="font-bold text-emerald-300">ACTIVE CASE: {activeCase.case_id}</span>
        </div>
        {activeCase.device_id && (
          <span className="text-muted-foreground">
            Device: <span className="text-foreground">{activeCase.device_id}</span>
          </span>
        )}
        {(activeCase.image_filename || activeCase.image_path) && (
          <span className="text-muted-foreground">
            Source: <span className="text-foreground">{activeCase.image_filename || activeCase.image_path}</span>
          </span>
        )}
        {activeCase.sha256 && (
          <span className="text-muted-foreground truncate max-w-[220px]">
            SHA-256: <span className="text-foreground">{activeCase.sha256}</span>
          </span>
        )}
      </div>
      <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/40 text-[10px] shrink-0">
        READ-ONLY FORENSIC IMAGE
      </Badge>
    </div>
  );
}
