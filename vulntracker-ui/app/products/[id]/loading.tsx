import { Loader2 } from "lucide-react";

export default function ProductDetailLoading() {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <Loader2 className="h-8 w-8 text-[#059669] animate-spin" />
    </div>
  );
}
