import { getEmailsCollection } from "@/lib/mongodb";
import { EmailDashboard } from "@/components/email-dashboard";
import type { MonitoredEmail } from "@/lib/types";

export const dynamic = "force-dynamic";

async function getEmails(): Promise<{ emails: MonitoredEmail[]; total: number }> {
  try {
    const collection = await getEmailsCollection();
    
    const [emails, total] = await Promise.all([
      collection
        .find({})
        .sort({ timestamp: -1 })
        .limit(50)
        .toArray(),
      collection.countDocuments({}),
    ]);

    return {
      emails: emails.map((e) => ({
        ...e,
        _id: e._id.toString(),
      })) as MonitoredEmail[],
      total,
    };
  } catch (error) {
    console.error("Error fetching emails:", error);
    return { emails: [], total: 0 };
  }
}

export default async function EmailsPage() {
  const { emails, total } = await getEmails();

  return (
    <main className="container mx-auto max-w-7xl px-4 py-6">
      <EmailDashboard 
        initialEmails={emails} 
        initialTotal={total} 
      />
    </main>
  );
}
