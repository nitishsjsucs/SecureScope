"use client";

import { cn, formatDate } from "@/lib/utils";
import type { ChatSession } from "@/lib/types";
import { 
  MessageSquare, 
  Plus, 
  Trash2, 
  MoreHorizontal,
  Clock
} from "lucide-react";
import { useState } from "react";

interface ChatSidebarProps {
  sessions: ChatSession[];
  currentSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  onNewSession: () => void;
  onDeleteSession: (sessionId: string) => void;
  className?: string;
}

interface SessionItemProps {
  session: ChatSession;
  isActive: boolean;
  onSelect: () => void;
  onDelete: () => void;
}

function SessionItem({ session, isActive, onSelect, onDelete }: SessionItemProps) {
  const [showMenu, setShowMenu] = useState(false);

  return (
    <div className="relative group">
      <button
        onClick={onSelect}
        className={cn(
          "w-full text-left px-3 py-2.5 rounded-lg transition-colors flex items-start gap-2",
          isActive 
            ? "bg-[#ECFDF5] text-[#059669]" 
            : "hover:bg-[#F9FAFB] text-[#4B5563]"
        )}
      >
        <MessageSquare className={cn(
          "h-4 w-4 flex-shrink-0 mt-0.5",
          isActive ? "text-[#059669]" : "text-[#9CA3AF]"
        )} />
        <div className="flex-1 min-w-0">
          <p className={cn(
            "text-sm truncate",
            isActive ? "font-medium" : ""
          )}>
            {session.title}
          </p>
          <p className="text-xs text-[#9CA3AF] flex items-center gap-1 mt-0.5">
            <Clock className="h-3 w-3" />
            {formatDate(session.updated_at)}
          </p>
        </div>
      </button>

      {/* Actions menu */}
      <div className={cn(
        "absolute right-2 top-2",
        showMenu ? "opacity-100" : "opacity-0 group-hover:opacity-100"
      )}>
        <button
          onClick={(e) => {
            e.stopPropagation();
            setShowMenu(!showMenu);
          }}
          className="p-1 rounded hover:bg-[#E5E7EB] transition-colors"
        >
          <MoreHorizontal className="h-4 w-4 text-[#6B7280]" />
        </button>

        {showMenu && (
          <>
            <div 
              className="fixed inset-0 z-10" 
              onClick={() => setShowMenu(false)} 
            />
            <div className="absolute right-0 top-full mt-1 w-32 bg-white rounded-lg shadow-lg border border-[#E5E7EB] overflow-hidden z-20">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete();
                  setShowMenu(false);
                }}
                className="w-full px-3 py-2 text-sm text-[#DC2626] hover:bg-[#FEF2F2] flex items-center gap-2"
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export function ChatSidebar({
  sessions,
  currentSessionId,
  onSelectSession,
  onNewSession,
  onDeleteSession,
  className,
}: ChatSidebarProps) {
  // Group sessions by date
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);
  
  const lastWeek = new Date(today);
  lastWeek.setDate(lastWeek.getDate() - 7);

  const grouped = {
    today: [] as ChatSession[],
    yesterday: [] as ChatSession[],
    thisWeek: [] as ChatSession[],
    older: [] as ChatSession[],
  };

  sessions.forEach((session) => {
    const date = new Date(session.updated_at);
    date.setHours(0, 0, 0, 0);

    if (date.getTime() === today.getTime()) {
      grouped.today.push(session);
    } else if (date.getTime() === yesterday.getTime()) {
      grouped.yesterday.push(session);
    } else if (date >= lastWeek) {
      grouped.thisWeek.push(session);
    } else {
      grouped.older.push(session);
    }
  });

  return (
    <div className={cn("flex flex-col h-full bg-white", className)}>
      {/* Header */}
      <div className="p-4 border-b border-[#E5E7EB]">
        <button
          onClick={onNewSession}
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-[#059669] text-white rounded-lg hover:bg-[#047857] transition-colors font-medium text-sm"
        >
          <Plus className="h-4 w-4" />
          New Chat
        </button>
      </div>

      {/* Session List */}
      <div className="flex-1 overflow-y-auto p-2">
        {sessions.length === 0 ? (
          <div className="text-center py-8 px-4">
            <MessageSquare className="h-10 w-10 text-[#D1D5DB] mx-auto mb-3" />
            <p className="text-sm text-[#6B7280]">
              No conversations yet
            </p>
            <p className="text-xs text-[#9CA3AF] mt-1">
              Start a new chat to begin
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {grouped.today.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-[#9CA3AF] uppercase tracking-wide px-3 mb-1">
                  Today
                </p>
                <div className="space-y-0.5">
                  {grouped.today.map((session) => (
                    <SessionItem
                      key={session._id}
                      session={session}
                      isActive={session._id === currentSessionId}
                      onSelect={() => onSelectSession(session._id)}
                      onDelete={() => onDeleteSession(session._id)}
                    />
                  ))}
                </div>
              </div>
            )}

            {grouped.yesterday.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-[#9CA3AF] uppercase tracking-wide px-3 mb-1">
                  Yesterday
                </p>
                <div className="space-y-0.5">
                  {grouped.yesterday.map((session) => (
                    <SessionItem
                      key={session._id}
                      session={session}
                      isActive={session._id === currentSessionId}
                      onSelect={() => onSelectSession(session._id)}
                      onDelete={() => onDeleteSession(session._id)}
                    />
                  ))}
                </div>
              </div>
            )}

            {grouped.thisWeek.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-[#9CA3AF] uppercase tracking-wide px-3 mb-1">
                  This Week
                </p>
                <div className="space-y-0.5">
                  {grouped.thisWeek.map((session) => (
                    <SessionItem
                      key={session._id}
                      session={session}
                      isActive={session._id === currentSessionId}
                      onSelect={() => onSelectSession(session._id)}
                      onDelete={() => onDeleteSession(session._id)}
                    />
                  ))}
                </div>
              </div>
            )}

            {grouped.older.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-[#9CA3AF] uppercase tracking-wide px-3 mb-1">
                  Older
                </p>
                <div className="space-y-0.5">
                  {grouped.older.map((session) => (
                    <SessionItem
                      key={session._id}
                      session={session}
                      isActive={session._id === currentSessionId}
                      onSelect={() => onSelectSession(session._id)}
                      onDelete={() => onDeleteSession(session._id)}
                    />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
