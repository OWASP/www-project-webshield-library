import { redirect } from "next/navigation";
import { getSession } from "../lib/auth.js";

export default async function Home() {
  redirect((await getSession()) ? "/claims" : "/login");
}
