export default function ChatLoading() {
  return (
    <main className="container mx-auto max-w-7xl px-4 py-6">
      <div className="mb-6">
        <div className="h-8 w-32 bg-[#E5E7EB] rounded animate-pulse" />
        <div className="h-4 w-64 bg-[#E5E7EB] rounded animate-pulse mt-2" />
      </div>

      <div className="flex h-[calc(100vh-180px)] bg-white rounded-xl border border-[#D1D5DB] overflow-hidden">
        {/* Sidebar skeleton */}
        <div className="w-72 border-r border-[#E5E7EB] p-4">
          <div className="h-10 bg-[#E5E7EB] rounded-lg animate-pulse mb-4" />
          <div className="space-y-2">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="h-14 bg-[#F3F4F6] rounded-lg animate-pulse" />
            ))}
          </div>
        </div>

        {/* Main area skeleton */}
        <div className="flex-1 flex flex-col">
          {/* Header */}
          <div className="px-4 py-3 border-b border-[#E5E7EB] bg-[#F9FAFB]">
            <div className="h-6 w-40 bg-[#E5E7EB] rounded animate-pulse" />
            <div className="h-4 w-32 bg-[#E5E7EB] rounded animate-pulse mt-1" />
          </div>

          {/* Messages area */}
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <div className="w-16 h-16 bg-[#E5E7EB] rounded-2xl animate-pulse mx-auto mb-4" />
              <div className="h-6 w-48 bg-[#E5E7EB] rounded animate-pulse mx-auto mb-2" />
              <div className="h-4 w-64 bg-[#E5E7EB] rounded animate-pulse mx-auto" />
            </div>
          </div>

          {/* Input area */}
          <div className="p-4 border-t border-[#E5E7EB] bg-[#F9FAFB]">
            <div className="h-12 bg-[#E5E7EB] rounded-xl animate-pulse" />
          </div>
        </div>
      </div>
    </main>
  );
}
