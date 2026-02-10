"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { cn } from "@/lib/utils";
import type { ChatMessage, ChatSession, RAGSource } from "@/lib/types";
import { ChatMessageBubble, TypingIndicator } from "./chat-message";
import { ChatSidebar } from "./chat-sidebar";
import { 
  Send, 
  Loader2, 
  Database,
  Sparkles,
  AlertCircle,
  PanelLeftClose,
  PanelLeft
} from "lucide-react";

interface ChatInterfaceProps {
  initialSessions: ChatSession[];
}

export function ChatInterface({ initialSessions }: ChatInterfaceProps) {
  const [sessions, setSessions] = useState<ChatSession[]>(initialSessions);
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Auto-resize textarea
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.style.height = "auto";
      inputRef.current.style.height = `${Math.min(inputRef.current.scrollHeight, 150)}px`;
    }
  }, [inputValue]);

  // Load session messages
  const loadSession = useCallback(async (sessionId: string) => {
    try {
      const response = await fetch(`/api/chat/sessions/${sessionId}`);
      if (response.ok) {
        const session = await response.json();
        setMessages(session.messages || []);
        setCurrentSessionId(sessionId);
      }
    } catch (err) {
      console.error("Error loading session:", err);
      setError("Failed to load conversation");
    }
  }, []);

  // Start new session
  const handleNewSession = () => {
    setCurrentSessionId(null);
    setMessages([]);
    setError(null);
    inputRef.current?.focus();
  };

  // Select existing session
  const handleSelectSession = (sessionId: string) => {
    if (sessionId !== currentSessionId) {
      loadSession(sessionId);
    }
  };

  // Delete session
  const handleDeleteSession = async (sessionId: string) => {
    try {
      const response = await fetch(`/api/chat/sessions/${sessionId}`, {
        method: "DELETE",
      });
      
      if (response.ok) {
        setSessions((prev) => prev.filter((s) => s._id !== sessionId));
        if (currentSessionId === sessionId) {
          handleNewSession();
        }
      }
    } catch (err) {
      console.error("Error deleting session:", err);
    }
  };

  // Send message
  const handleSendMessage = async () => {
    const message = inputValue.trim();
    if (!message || isLoading) return;

    setInputValue("");
    setError(null);
    setIsLoading(true);

    // Optimistically add user message
    const userMessage: ChatMessage = {
      id: `temp-${Date.now()}`,
      role: "user",
      content: message,
      timestamp: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, userMessage]);

    try {
      const response = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message,
          sessionId: currentSessionId,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to send message");
      }

      const data = await response.json();
      
      // Update messages with actual response from server
      setMessages((prev) => {
        // Remove the temp user message and add the real user + assistant messages
        const filtered = prev.filter((m) => m.id !== userMessage.id);
        return [
          ...filtered,
          data.userMessage,
          data.assistantMessage,
        ];
      });

      // Update session ID if this was a new conversation
      if (!currentSessionId && data.sessionId) {
        setCurrentSessionId(data.sessionId);
        
        // Refresh sessions list
        const sessionsResponse = await fetch("/api/chat/sessions");
        if (sessionsResponse.ok) {
          const sessionsData = await sessionsResponse.json();
          setSessions(sessionsData.sessions);
        }
      }
    } catch (err) {
      console.error("Error sending message:", err);
      setError("Failed to send message. Please try again.");
      // Remove the optimistic user message on error
      setMessages((prev) => prev.filter((m) => m.id !== userMessage.id));
    } finally {
      setIsLoading(false);
    }
  };

  // Handle keyboard shortcuts
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  return (
    <div className="flex h-[calc(100vh-180px)] bg-white rounded-xl border border-[#D1D5DB] overflow-hidden">
      {/* Sidebar */}
      <div className={cn(
        "border-r border-[#E5E7EB] transition-all duration-300 flex-shrink-0",
        sidebarCollapsed ? "w-0 overflow-hidden" : "w-72"
      )}>
        <ChatSidebar
          sessions={sessions}
          currentSessionId={currentSessionId}
          onSelectSession={handleSelectSession}
          onNewSession={handleNewSession}
          onDeleteSession={handleDeleteSession}
        />
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Chat Header */}
        <div className="px-4 py-3 border-b border-[#E5E7EB] flex items-center justify-between bg-[#F9FAFB]">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="p-1.5 rounded-lg hover:bg-[#E5E7EB] transition-colors"
              title={sidebarCollapsed ? "Show sidebar" : "Hide sidebar"}
            >
              {sidebarCollapsed ? (
                <PanelLeft className="h-5 w-5 text-[#6B7280]" />
              ) : (
                <PanelLeftClose className="h-5 w-5 text-[#6B7280]" />
              )}
            </button>
            <div>
              <h2 className="font-semibold text-[#1F2937]">CVE Assistant</h2>
              <p className="text-xs text-[#6B7280] flex items-center gap-1">
                <Database className="h-3 w-3" />
                330K+ CVEs available
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs text-[#9CA3AF]">
            <Sparkles className="h-4 w-4" />
            Powered by GPT-4o
          </div>
        </div>

        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto p-4">
          {messages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-center px-4">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-[#059669] to-[#047857] flex items-center justify-center mb-4">
                <Sparkles className="h-8 w-8 text-white" />
              </div>
              <h3 className="text-xl font-semibold text-[#1F2937] mb-2">
                Ask me about CVEs
              </h3>
              <p className="text-[#6B7280] max-w-md mb-6">
                I can help you search and understand vulnerabilities from the CVE database.
                Ask about specific CVEs, products, or security topics.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-w-lg">
                {[
                  "What are the latest critical CVEs?",
                  "Tell me about CVE-2024-3094",
                  "What vulnerabilities affect Apache?",
                  "Show me Log4j related CVEs",
                ].map((suggestion) => (
                  <button
                    key={suggestion}
                    onClick={() => {
                      setInputValue(suggestion);
                      inputRef.current?.focus();
                    }}
                    className="text-left px-3 py-2 rounded-lg border border-[#E5E7EB] text-sm text-[#4B5563] hover:bg-[#F9FAFB] hover:border-[#D1D5DB] transition-colors"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <>
              {messages.map((message) => (
                <ChatMessageBubble key={message.id} message={message} />
              ))}
              {isLoading && <TypingIndicator />}
              <div ref={messagesEndRef} />
            </>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <div className="px-4 py-2 bg-[#FEF2F2] border-t border-[#FECACA]">
            <p className="text-sm text-[#DC2626] flex items-center gap-2">
              <AlertCircle className="h-4 w-4" />
              {error}
            </p>
          </div>
        )}

        {/* Input Area */}
        <div className="p-4 border-t border-[#E5E7EB] bg-[#F9FAFB]">
          <div className="flex items-end gap-2">
            <div className="flex-1 relative">
              <textarea
                ref={inputRef}
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about CVEs, vulnerabilities, or security topics..."
                rows={1}
                className="w-full px-4 py-3 pr-12 rounded-xl border border-[#D1D5DB] bg-white text-[#1F2937] placeholder:text-[#9CA3AF] focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-transparent resize-none text-sm"
                disabled={isLoading}
              />
            </div>
            <button
              onClick={handleSendMessage}
              disabled={!inputValue.trim() || isLoading}
              className={cn(
                "p-3 rounded-xl transition-colors flex-shrink-0",
                inputValue.trim() && !isLoading
                  ? "bg-[#059669] text-white hover:bg-[#047857]"
                  : "bg-[#E5E7EB] text-[#9CA3AF] cursor-not-allowed"
              )}
            >
              {isLoading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <Send className="h-5 w-5" />
              )}
            </button>
          </div>
          <p className="text-xs text-[#9CA3AF] mt-2 text-center">
            Press Enter to send, Shift+Enter for new line
          </p>
        </div>
      </div>
    </div>
  );
}
