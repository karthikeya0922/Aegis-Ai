import Link from "next/link";
import { Shield, ShieldAlert, Key, Zap, BrainCircuit, HardDrive, EyeOff } from "lucide-react";
import { CosmicBackground } from "@/components/shell/CosmicBackground";

const features = [
  {
    icon: <EyeOff className="w-6 h-6 text-aegis-neon" />,
    title: "PII Redaction",
    description: "Automatically detect and redact sensitive user data before it hits external APIs.",
  },
  {
    icon: <Key className="w-6 h-6 text-aegis-neon" />,
    title: "Secret Detection",
    description: "Prevent API keys, tokens, and credentials from leaking in prompt payloads.",
  },
  {
    icon: <ShieldAlert className="w-6 h-6 text-aegis-neon" />,
    title: "Injection Defense",
    description: "Block malicious prompt injections and jailbreak attempts in real-time.",
  },
  {
    icon: <Zap className="w-6 h-6 text-aegis-neon" />,
    title: "Smart Routing",
    description: "Route requests dynamically to the most cost-effective and capable models.",
  },
  {
    icon: <HardDrive className="w-6 h-6 text-aegis-neon" />,
    title: "Semantic Cache",
    description: "Cache responses intelligently based on semantic meaning to save costs and reduce latency.",
  },
  {
    icon: <BrainCircuit className="w-6 h-6 text-aegis-neon" />,
    title: "Hallucination Firewall",
    description: "Monitor and filter model outputs to prevent hallucinated facts and unsanctioned behavior.",
  },
];

export default function LandingPage() {
  return (
    <main className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden bg-black text-white">
      <div className="absolute inset-0 z-0">
        <CosmicBackground />
      </div>

      <div className="relative z-10 container mx-auto px-6 py-24 flex-grow flex flex-col items-center justify-center text-center">
        {/* Branding */}
        <div className="flex items-center gap-3 mb-8">
          <Shield className="w-12 h-12 text-aegis-neon" />
          <h1 className="text-4xl font-extrabold tracking-widest uppercase">Aegis</h1>
        </div>

        {/* Hero */}
        <h2 className="text-5xl md:text-7xl font-bold mb-6 tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">
          Zero-Trust AI Gateway
        </h2>
        <p className="text-xl md:text-2xl text-gray-400 mb-12 max-w-3xl">
          Redact PII. Block injections. Route smart. Audit everything.
        </p>

        {/* CTAs */}
        <div className="flex flex-col sm:flex-row gap-6 mb-24">
          <Link
            href="/playground"
            className="px-8 py-4 rounded-full bg-aegis-neon text-black font-semibold text-lg hover:bg-aegis-neon/90 transition-colors flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(57,255,20,0.3)]"
          >
            Launch Inspector &rarr;
          </Link>
          <Link
            href="https://github.com"
            target="_blank"
            rel="noopener noreferrer"
            className="px-8 py-4 rounded-full bg-white/10 text-white font-semibold text-lg hover:bg-white/20 transition-colors border border-white/20 flex items-center justify-center gap-2 backdrop-blur-sm"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
            </svg>
            GitHub
          </Link>
        </div>

        {/* Feature Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 w-full max-w-6xl text-left">
          {features.map((feature, idx) => (
            <div
              key={idx}
              className="p-6 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-sm hover:bg-white/10 transition-colors"
            >
              <div className="mb-4 bg-black/50 w-12 h-12 flex items-center justify-center rounded-lg border border-white/5">
                {feature.icon}
              </div>
              <h3 className="text-xl font-semibold mb-2 text-white">{feature.title}</h3>
              <p className="text-gray-400 leading-relaxed">{feature.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Footer */}
      <footer className="relative z-10 w-full py-8 text-center text-gray-500 border-t border-white/10 bg-black/50 backdrop-blur-md">
        <p>&copy; {new Date().getFullYear()} Aegis AI. All rights reserved.</p>
      </footer>
    </main>
  );
}
