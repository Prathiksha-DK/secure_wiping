"use client";

import React, { useEffect, useState } from "react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { AlertTriangle, Lock } from "lucide-react";

export default function NavigationLockModal() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const handleShow = () => {
      setOpen(true);
    };

    window.addEventListener("faris-show-lock-alert", handleShow);
    return () => {
      window.removeEventListener("faris-show-lock-alert", handleShow);
    };
  }, []);

  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogContent className="max-w-md border-amber-500/30 bg-card">
        <AlertDialogHeader>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-full bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
              <Lock className="w-5 h-5" />
            </div>
            <AlertDialogTitle className="text-base font-bold">
              Navigation Locked
            </AlertDialogTitle>
          </div>
          <AlertDialogDescription className="text-sm pt-2 text-foreground font-medium leading-relaxed">
            Navigation is disabled while FARIS recovery is in progress. Please wait until the process is completed.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter className="pt-2">
          <AlertDialogAction
            onClick={() => setOpen(false)}
            className="bg-amber-600 hover:bg-amber-700 text-white font-semibold text-xs px-4 py-2"
          >
            I Understand
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
