import Link from "next/link";
import { Button } from "@/components/ui/button";
import { FileQuestion } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center py-16 space-y-6">
      <FileQuestion className="h-16 w-16 text-slate-400" />
      <div className="text-center space-y-2">
        <h2 className="text-2xl font-semibold text-slate-900">Not Found</h2>
        <p className="text-slate-600">
          The page you&apos;re looking for doesn&apos;t exist.
        </p>
      </div>
      <div className="flex gap-4">
        <Button asChild>
          <Link href="/">View CVEs</Link>
        </Button>
        <Button variant="outline" asChild>
          <Link href="/vendors">View Vendors</Link>
        </Button>
      </div>
    </div>
  );
}
