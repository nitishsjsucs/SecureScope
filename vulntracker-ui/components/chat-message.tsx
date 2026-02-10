"use client";

import { cn } from "@/lib/utils";
import type { ChatMessage, RAGSource, SeverityLevel } from "@/lib/types";
import { User, Bot, ExternalLink, AlertTriangle } from "lucide-react";
import Link from "next/link";
import ReactMarkdown from "react-markdown";

interface ChatMessageProps {
  message: ChatMessage;
  className?: string;
}

function getSeverityColor(severity?: SeverityLevel) {
  switch (severity) {
    case "critical":
      return "bg-[#DC2626] text-white";
    case "high":
      return "bg-[#EA580C] text-white";
    case "medium":
      return "bg-[#FBBF24] text-[#1F2937]";
    case "low":
      return "bg-[#059669] text-white";
    default:
      return "bg-[#E5E7EB] text-[#4B5563]";
  }
}

function SourceCard({ source }: { source: RAGSource }) {
  return (
    <Link
      href={source.url || `/cve/${source.id}`}
      className="block p-3 rounded-lg bg-[#F9FAFB] hover:bg-[#F3F4F6] transition-colors border border-[#E5E7EB] group"
    >
      <div className="flex items-center justify-between gap-2 mb-1.5">
        <div className="flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 text-[#DC2626] flex-shrink-0" />
          <span className="text-sm font-semibold text-[#1F2937] font-mono">
            {source.title || source.id}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {source.severity && (
            <span className={cn(
              "text-xs px-1.5 py-0.5 rounded font-medium uppercase",
              getSeverityColor(source.severity)
            )}>
              {source.severity}
            </span>
          )}
          <ExternalLink className="h-3 w-3 text-[#9CA3AF] group-hover:text-[#6B7280] flex-shrink-0" />
        </div>
      </div>
      <p className="text-xs text-[#6B7280] line-clamp-2 pl-6">
        {source.snippet}
      </p>
    </Link>
  );
}

export function ChatMessageBubble({ message, className }: ChatMessageProps) {
  const isUser = message.role === "user";
  const isSystem = message.role === "system";

  if (isSystem) {
    return (
      <div className={cn("flex justify-center my-4", className)}>
        <div className="text-xs text-[#9CA3AF] bg-[#F9FAFB] px-3 py-1 rounded-full">
          {message.content}
        </div>
      </div>
    );
  }

  return (
    <div className={cn(
      "flex gap-3 mb-4",
      isUser ? "flex-row-reverse" : "flex-row",
      className
    )}>
      {/* Avatar */}
      <div className={cn(
        "w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0",
        isUser ? "bg-[#059669]" : "bg-[#3B82F6]"
      )}>
        {isUser ? (
          <User className="h-4 w-4 text-white" />
        ) : (
          <Bot className="h-4 w-4 text-white" />
        )}
      </div>

      {/* Content */}
      <div className={cn(
        "flex flex-col max-w-[80%]",
        isUser ? "items-end" : "items-start"
      )}>
        {/* Message bubble */}
        <div className={cn(
          "rounded-2xl px-4 py-2.5",
          isUser 
            ? "bg-[#059669] text-white rounded-br-md" 
            : "bg-[#F3F4F6] text-[#1F2937] rounded-bl-md"
        )}>
          {isUser ? (
            <p className="text-sm whitespace-pre-wrap leading-relaxed">
              {message.content}
            </p>
          ) : (
            <div className="text-sm leading-relaxed prose prose-sm prose-gray max-w-none prose-p:my-1 prose-ul:my-1 prose-ol:my-1 prose-li:my-0 prose-pre:bg-[#1F2937] prose-pre:text-white prose-code:text-[#DC2626] prose-code:bg-[#FEF2F2] prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:before:content-none prose-code:after:content-none prose-a:text-[#2563EB] prose-strong:text-[#1F2937]">
              <ReactMarkdown>{message.content}</ReactMarkdown>
            </div>
          )}
        </div>

        {/* Sources (only for assistant messages) */}
        {!isUser && message.sources && message.sources.length > 0 && (
          <div className="mt-3 w-full">
            <p className="text-xs font-medium text-[#6B7280] mb-2">
              Sources ({message.sources.length} CVEs)
            </p>
            <div className="space-y-2">
              {message.sources.slice(0, 5).map((source, index) => (
                <SourceCard key={`${message.id}-${source.id}-${index}`} source={source} />
              ))}
              {message.sources.length > 5 && (
                <p className="text-xs text-[#9CA3AF]">
                  +{message.sources.length - 5} more sources
                </p>
              )}
            </div>
          </div>
        )}

        {/* Timestamp */}
        <span className="text-xs text-[#9CA3AF] mt-1">
          {new Date(message.timestamp).toLocaleTimeString([], { 
            hour: "2-digit", 
            minute: "2-digit" 
          })}
        </span>
      </div>
    </div>
  );
}

// Typing indicator for when assistant is generating
export function TypingIndicator() {
  return (
    <div className="flex gap-3 mb-4">
      <div className="w-8 h-8 rounded-full bg-[#3B82F6] flex items-center justify-center flex-shrink-0">
        <Bot className="h-4 w-4 text-white" />
      </div>
      <div className="bg-[#F3F4F6] rounded-2xl rounded-bl-md px-4 py-3">
        <div className="flex gap-1">
          <span className="w-2 h-2 bg-[#9CA3AF] rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
          <span className="w-2 h-2 bg-[#9CA3AF] rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
          <span className="w-2 h-2 bg-[#9CA3AF] rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
        </div>
      </div>
    </div>
  );
}
