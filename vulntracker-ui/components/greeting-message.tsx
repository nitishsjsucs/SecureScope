"use client";

import type { DashboardStats } from "./greeting-banner";

function getGreeting(): string {
  const hour = new Date().getHours();
  if (hour >= 5 && hour < 12) return "Good morning";
  if (hour >= 12 && hour < 17) return "Good afternoon";
  if (hour >= 17 && hour < 21) return "Good evening";
  return "Good evening";
}

function getDayOfWeek(): string {
  const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  return days[new Date().getDay()];
}

function formatNumber(num: number): string {
  return num.toLocaleString("en-US");
}

interface GreetingMessageProps {
  stats: DashboardStats | null;
}

export function GreetingMessage({ stats }: GreetingMessageProps) {
  const greeting = getGreeting();
  const dayOfWeek = getDayOfWeek();

  const renderMessage = () => {
    if (!stats) {
      return (
        <p className="text-base text-[#4B5563] leading-relaxed">
          Welcome back! Ready to explore the vulnerability landscape?
        </p>
      );
    }

    const { total_cves, total_products, cves_affecting_products, critical_affecting, high_affecting } = stats;
    const criticalAndHigh = critical_affecting + high_affecting;

    // No products tracked yet
    if (total_products === 0) {
      return (
        <p className="text-base text-[#4B5563] leading-relaxed">
          You&apos;re looking at a sexy {dayOfWeek.toLowerCase()} ahead. With{" "}
          <span className="font-semibold text-[#059669]">{formatNumber(total_cves)}</span>{" "}
          CVEs in the database, why not{" "}
          <a href="/products/new" className="text-[#059669] hover:text-[#047857] underline underline-offset-2 font-medium">
            add a product
          </a>{" "}
          to start tracking vulnerabilities?
        </p>
      );
    }

    // Products tracked, no CVEs affecting them
    if (cves_affecting_products === 0) {
      return (
        <p className="text-base text-[#4B5563] leading-relaxed">
          Looking like a sexy {dayOfWeek.toLowerCase()} ahead! Out of{" "}
          <span className="font-semibold text-[#1F2937]">{formatNumber(total_cves)}</span>{" "}
          CVEs detected,{" "}
          <span className="font-semibold text-[#059669]">none</span>{" "}
          affect your{" "}
          <span className="font-semibold text-[#059669]">{formatNumber(total_products)}</span>{" "}
          tracked {total_products === 1 ? "product" : "products"}. Keep it up!
        </p>
      );
    }

    // Products tracked with CVEs affecting them
    if (criticalAndHigh > 0) {
      return (
        <p className="text-base text-[#4B5563] leading-relaxed">
          Heads up this {dayOfWeek.toLowerCase()}. Of{" "}
          <span className="font-semibold text-[#1F2937]">{formatNumber(total_cves)}</span>{" "}
          CVEs tracked,{" "}
          <span className="font-semibold text-[#DC2626]">{formatNumber(cves_affecting_products)}</span>{" "}
          affect your{" "}
          <span className="font-semibold text-[#1F2937]">{formatNumber(total_products)}</span>{" "}
          {total_products === 1 ? "product" : "products"} &mdash; including{" "}
          {critical_affecting > 0 && (
            <>
              <span className="font-semibold text-[#DC2626]">{formatNumber(critical_affecting)}</span>{" "}
              critical
            </>
          )}
          {critical_affecting > 0 && high_affecting > 0 && " and "}
          {high_affecting > 0 && (
            <>
              <span className="font-semibold text-[#EA580C]">{formatNumber(high_affecting)}</span>{" "}
              high
            </>
          )}
          . Time to patch!
        </p>
      );
    }

    // Only medium/low CVEs affecting products
    return (
      <p className="text-base text-[#4B5563] leading-relaxed">
        Looking good this {dayOfWeek.toLowerCase()}! Of{" "}
        <span className="font-semibold text-[#1F2937]">{formatNumber(total_cves)}</span>{" "}
        CVEs tracked,{" "}
        <span className="font-semibold text-[#D97706]">{formatNumber(cves_affecting_products)}</span>{" "}
        affect your{" "}
        <span className="font-semibold text-[#1F2937]">{formatNumber(total_products)}</span>{" "}
        {total_products === 1 ? "product" : "products"} &mdash; all medium or low severity. Stay vigilant!
      </p>
    );
  };

  return (
    <div className="py-4">
      <h1 className="font-display text-2xl font-semibold text-[#1F2937] mb-1.5 tracking-tight">
        {greeting}!
      </h1>
      {renderMessage()}
    </div>
  );
}
