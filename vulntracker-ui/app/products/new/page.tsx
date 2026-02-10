"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Github,
  ArrowLeft,
  Search,
  Sparkles,
  Check,
  AlertCircle,
  ChevronRight,
  Package,
  Bell,
  Shield,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { UserProduct, Dependency } from "@/lib/types";

type Step = "input" | "analyzing" | "results" | "error";

export default function NewProductPage() {
  const router = useRouter();
  const [githubUrl, setGithubUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState<Step>("input");
  const [product, setProduct] = useState<UserProduct | null>(null);

  const isValidGithubUrl = (url: string) => {
    return /^https?:\/\/github\.com\/[^\/]+\/[^\/]+\/?$/.test(url);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!isValidGithubUrl(githubUrl)) {
      setError("Please enter a valid GitHub repository URL");
      return;
    }

    setStep("analyzing");

    try {
      const createRes = await fetch("/api/products", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ github_url: githubUrl }),
      });

      if (!createRes.ok) {
        const data = await createRes.json();
        if (createRes.status === 409) {
          router.push(`/products/${data.product_id}`);
          return;
        }
        throw new Error(data.error || "Failed to create product");
      }

      const newProduct = await createRes.json();

      const analyzeRes = await fetch(`/api/products/${newProduct._id}/analyze`, {
        method: "POST",
      });

      const analyzeData = await analyzeRes.json();

      if (!analyzeRes.ok) {
        throw new Error(analyzeData.message || analyzeData.error || "Analysis failed");
      }

      setProduct(analyzeData);
      setStep("results");
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Something went wrong";
      setError(errorMessage);
      setStep("error");
    }
  };

  const handleTrackDependency = async (depIndex: number, tracked: boolean) => {
    if (!product) return;

    const updatedDeps = product.dependencies.map((d, i) =>
      i === depIndex ? { ...d, tracked } : d
    );

    try {
      const res = await fetch(`/api/products/${product._id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ dependencies: updatedDeps }),
      });

      if (res.ok) {
        const updated = await res.json();
        setProduct(updated);
      }
    } catch {
      // Handle error silently
    }
  };

  const handleFinish = () => {
    router.push(`/products/${product?._id}`);
  };

  const handleRetry = () => {
    setStep("input");
    setError(null);
  };

  return (
    <div className="min-h-[70vh] flex flex-col">
      {step === "input" && (
        <InputStep
          githubUrl={githubUrl}
          setGithubUrl={setGithubUrl}
          error={error}
          onSubmit={handleSubmit}
          isValidUrl={isValidGithubUrl(githubUrl)}
        />
      )}

      {step === "analyzing" && <AnalyzingStep />}

      {step === "error" && (
        <ErrorStep error={error} onRetry={handleRetry} />
      )}

      {step === "results" && product && (
        <ResultsStep
          product={product}
          onTrackDependency={handleTrackDependency}
          onFinish={handleFinish}
        />
      )}
    </div>
  );
}

// Google-style minimal input
function InputStep({
  githubUrl,
  setGithubUrl,
  error,
  onSubmit,
  isValidUrl,
}: {
  githubUrl: string;
  setGithubUrl: (url: string) => void;
  error: string | null;
  onSubmit: (e: React.FormEvent) => void;
  isValidUrl: boolean;
}) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center px-4">
      {/* Logo / Brand */}
      <div className="mb-8 text-center">
        <div className="inline-flex items-center gap-3 mb-3">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-[#059669] to-[#047857] flex items-center justify-center">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <span className="text-3xl font-bold text-[#1F2937]">SexySecure</span>
        </div>
      </div>

      {/* Search Bar */}
      <form onSubmit={onSubmit} className="w-full max-w-2xl">
        <div className={cn(
          "relative flex items-center rounded-full border-2 bg-white shadow-sm hover:shadow-md transition-shadow",
          error ? "border-[#EB5B3C]" : isValidUrl ? "border-[#059669]" : "border-[#D1D5DB]"
        )}>
          <div className="pl-5">
            <Github className="h-5 w-5 text-[#6B7280]" />
          </div>
          <input
            type="url"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            placeholder="Paste a GitHub repository URL..."
            className="flex-1 px-4 py-4 bg-transparent text-[#1F2937] placeholder-[#6B7280] focus:outline-none text-lg"
            autoFocus
          />
          {isValidUrl && (
            <div className="pr-2">
              <Check className="h-5 w-5 text-[#059669]" />
            </div>
          )}
          <button
            type="submit"
            disabled={!isValidUrl}
            className={cn(
              "mr-2 p-3 rounded-full transition-all",
              isValidUrl 
                ? "bg-[#059669] hover:bg-[#047857] text-white cursor-pointer" 
                : "bg-[#F9FAFB] text-[#6B7280] cursor-not-allowed"
            )}
          >
            <Search className="h-5 w-5" />
          </button>
        </div>
        
        {error && (
          <p className="mt-3 text-sm text-[#EB5B3C] text-center flex items-center justify-center gap-1">
            <AlertCircle className="h-4 w-4" />
            {error}
          </p>
        )}
      </form>

      {/* Subtle description */}
      <p className="mt-6 text-[#6B7280] text-sm text-center max-w-md">
        We&apos;ll analyze your repository and match CVEs to your dependencies.
        <br />
        <span className="text-[#4B5563]">Get alerts when new vulnerabilities affect your stack.</span>
      </p>

      {/* Back link - subtle at bottom */}
      <Link
        href="/products"
        className="mt-12 text-sm text-[#6B7280] hover:text-[#4B5563] transition-colors"
      >
        ← Back to products
      </Link>
    </div>
  );
}

// Analyzing step with centered spinner
function AnalyzingStep() {
  return (
    <div className="flex-1 flex flex-col items-center justify-center">
      <div className="relative w-20 h-20 mb-6">
        <div className="absolute inset-0 rounded-full border-4 border-[#D1D5DB]" />
        <div className="absolute inset-0 rounded-full border-4 border-[#059669] border-t-transparent animate-spin" />
        <div className="absolute inset-0 flex items-center justify-center">
          <Sparkles className="h-8 w-8 text-[#059669]" />
        </div>
      </div>
      <h2 className="text-xl font-semibold text-[#1F2937] mb-2">Analyzing Repository</h2>
      <p className="text-[#4B5563] text-center">
        Scanning dependencies and matching CVEs...
      </p>
    </div>
  );
}

// Error step
function ErrorStep({
  error,
  onRetry,
}: {
  error: string | null;
  onRetry: () => void;
}) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center">
      <div className="w-16 h-16 rounded-2xl bg-[#FEF0ED] flex items-center justify-center mb-4">
        <AlertCircle className="h-8 w-8 text-[#EB5B3C]" />
      </div>
      <h2 className="text-xl font-semibold text-[#1F2937] mb-2">Analysis Failed</h2>
      <p className="text-[#4B5563] max-w-md text-center mb-6">
        {error || "Something went wrong while analyzing the repository."}
      </p>
      <Button
        onClick={onRetry}
        variant="outline"
        className="border-[#D1D5DB] text-[#1F2937] hover:border-[#059669] hover:text-[#059669]"
      >
        <ArrowLeft className="h-4 w-4 mr-2" />
        Try Again
      </Button>
    </div>
  );
}

// Results step - compact
function ResultsStep({
  product,
  onTrackDependency,
  onFinish,
}: {
  product: UserProduct;
  onTrackDependency: (index: number, tracked: boolean) => void;
  onFinish: () => void;
}) {
  const groupedDeps = product.dependencies.reduce((acc, dep, index) => {
    if (!acc[dep.type]) acc[dep.type] = [];
    acc[dep.type].push({ ...dep, index });
    return acc;
  }, {} as Record<string, (Dependency & { index: number })[]>);

  const typeLabels: Record<string, string> = {
    npm: "npm",
    pip: "pip",
    go: "Go",
    cargo: "Cargo",
    gem: "Gem",
    maven: "Maven",
    gradle: "Gradle",
    composer: "Composer",
    nuget: "NuGet",
    other: "Other",
  };

  const directDeps = product.dependencies.filter(d => d.depth === 0).length;
  const transitiveDeps = product.dependencies.filter(d => d.depth > 0).length;

  return (
    <div className="max-w-3xl mx-auto w-full space-y-6 py-4">
      {/* Success Header */}
      <div className="flex items-center gap-4 p-4 rounded-xl bg-[#ECFDF5]">
        <div className="w-12 h-12 rounded-xl bg-[#059669] flex items-center justify-center">
          <Check className="h-6 w-6 text-white" />
        </div>
        <div className="flex-1">
          <h2 className="font-semibold text-[#1F2937]">{product.name}</h2>
          <p className="text-sm text-[#4B5563]">
            {product.total_dependencies} dependencies ({directDeps} direct, {transitiveDeps} transitive)
          </p>
        </div>
        <Button
          onClick={onFinish}
          className="bg-[#059669] hover:bg-[#047857] text-white"
        >
          View Dashboard
          <ChevronRight className="h-4 w-4 ml-1" />
        </Button>
      </div>

      {/* Dependencies Grid */}
      {product.dependencies.length > 0 ? (
        <div className="grid gap-3 md:grid-cols-2">
          {Object.entries(groupedDeps).map(([type, deps]) => (
            <Card key={type} className="border-[#D1D5DB]">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <span className="px-2 py-0.5 text-xs font-medium rounded bg-[#F9FAFB] text-[#4B5563]">
                    {typeLabels[type] || type}
                  </span>
                  <span className="text-xs text-[#6B7280]">{deps.length} packages</span>
                </div>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {deps.slice(0, 10).map((dep) => (
                    <div
                      key={dep.index}
                      className="flex items-center justify-between py-1.5 px-2 rounded hover:bg-[#F9FAFB] transition-colors"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <Package className="h-3.5 w-3.5 text-[#6B7280] flex-shrink-0" />
                        <span className="text-sm text-[#1F2937] truncate">{dep.name}</span>
                        {dep.depth > 0 && (
                          <span className="text-xs text-[#6B7280]">L{dep.depth}</span>
                        )}
                      </div>
                      <button
                        onClick={() => onTrackDependency(dep.index, !dep.tracked)}
                        className={cn(
                          "flex-shrink-0 w-5 h-5 rounded border-2 transition-colors",
                          dep.tracked
                            ? "bg-[#059669] border-[#059669]"
                            : "border-[#D1D5DB] hover:border-[#059669]"
                        )}
                      >
                        {dep.tracked && <Check className="h-3 w-3 text-white m-auto" />}
                      </button>
                    </div>
                  ))}
                  {deps.length > 10 && (
                    <p className="text-xs text-[#6B7280] text-center py-2">
                      +{deps.length - 10} more
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <Card className="border-[#D1D5DB]">
          <CardContent className="p-8 text-center">
            <Package className="h-10 w-10 text-[#6B7280] mx-auto mb-2" />
            <p className="text-[#4B5563]">No dependencies detected</p>
          </CardContent>
        </Card>
      )}

      {/* Alert notice */}
      <div className="flex items-center gap-3 p-3 rounded-lg bg-[#F9FAFB] text-sm">
        <Bell className="h-4 w-4 text-[#059669]" />
        <span className="text-[#4B5563]">
          You&apos;ll receive alerts when new CVEs match your tracked dependencies.
        </span>
      </div>
    </div>
  );
}
