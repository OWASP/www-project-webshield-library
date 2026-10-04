import { redirect } from "next/navigation";
import { getSession } from "../../lib/auth.js";
import { DEMO_USERS } from "../../lib/users.js";
import { LoginForm } from "./LoginForm.js";

export default async function LoginPage() {
  if (await getSession()) redirect("/claims");
  return (
    <div className="panel" style={{ maxWidth: 520, margin: "40px auto" }}>
      <h1>Sign in</h1>
      <LoginForm />
      <h2>Demo accounts</h2>
      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Password</th>
            <th>Role · team</th>
          </tr>
        </thead>
        <tbody>
          {DEMO_USERS.map((user) => (
            <tr key={user.id}>
              <td>{user.username}</td>
              <td>
                <code>{user.password}</code>
              </td>
              <td>
                {user.roles.join(", ")} · {user.team}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="hint">Demo only: real passwords never appear on a page or in source code.</p>
    </div>
  );
}
