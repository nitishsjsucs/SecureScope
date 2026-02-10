"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { ArrowDownAZ, ArrowUpAZ } from "lucide-react";
import type { CveSortOption } from "@/lib/api";

interface SortSelectProps {
  value: CveSortOption;
  onChange: (value: CveSortOption) => void;
  className?: string;
}

const sortOptions: { value: CveSortOption; label: string }[] = [
  { value: "-updated_at", label: "Recently Updated" },
  { value: "updated_at", label: "Oldest Updated" },
  { value: "-created_at", label: "Recently Published" },
  { value: "created_at", label: "Oldest Published" },
  { value: "-cvss", label: "Highest CVSS Score" },
  { value: "cvss", label: "Lowest CVSS Score" },
];

export function SortSelect({ value, onChange, className }: SortSelectProps) {
  return (
    <Select value={value} onValueChange={(v) => onChange(v as CveSortOption)}>
      <SelectTrigger className={cn("w-[200px]", className)}>
        <SelectValue placeholder="Sort by..." />
      </SelectTrigger>
      <SelectContent>
        {sortOptions.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
