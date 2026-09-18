import { Playground } from "@/components/playground/Playground";

export const metadata = { title: "Live Inspector — Aegis" };

export default function PlaygroundPage() {
  return (
    <div className="flex flex-col gap-14">
      <div className="flex flex-wrap items-center justify-between gap-14">
        <h1 className="m-0 text-5xl font-bold tracking-tight">Live Inspector</h1>
      </div>
      <Playground />
    </div>
  );
}
