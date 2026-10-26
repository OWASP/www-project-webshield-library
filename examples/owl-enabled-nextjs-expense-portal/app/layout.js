import Link from "next/link";
import { checkPermission } from "@owasp-webshield/next";
import { getSession } from "../lib/auth.js";
import { portal } from "../lib/portal.js";
import { signOut } from "./actions.js";
import "./globals.css";

export const metadata = { title: "OWL Expense Portal" };

export default async function RootLayout({ children }) {
  const session = await getSession();
  const isFinance = session && checkPermission({ session, action: "view", resource: "audit" }, portal().owl).allowed;

  return (
    <html lang="en">
      <body>
        <header className="topbar">
          <Link href="/claims" className="brand">
            OWL Expense Portal
          </Link>
          {session && (
            <nav>
              <Link href="/claims">Claims</Link>
              <Link href="/claims/new">New claim</Link>
              <Link href="/profile">Payout account</Link>
              {isFinance && <Link href="/finance">Finance &amp; security</Link>}
              <span className="who">
                {session.metadata.name} · {session.roles.join(", ")} · {session.metadata.team}
              </span>
              <form action={signOut}>
                <button type="submit" className="link">
                  Sign out
                </button>
              </form>
            </nav>
          )}
        </header>
        <main>{children}</main>
      </body>
    </html>
  );
}
