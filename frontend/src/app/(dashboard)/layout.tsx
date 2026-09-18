import { AppShell } from "@/components/shell/AppShell";
import { DashboardProvider } from "@/lib/dashboard-context";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <DashboardProvider>
      <AppShell>{children}</AppShell>
    </DashboardProvider>
  );
}
