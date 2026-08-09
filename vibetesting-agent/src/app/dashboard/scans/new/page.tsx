import { RunScanForm } from '@/components/forms';

export default function NewScanPage() {
  return (
    <div className="space-y-4">
      <h1 className="mono text-2xl font-bold">Ad-hoc scan</h1>
      <p className="text-sm text-[var(--mut)]">
        Point VibeTesting Agent at any URL you are authorized to test. Counts against your monthly quota.
      </p>
      <RunScanForm />
    </div>
  );
}
