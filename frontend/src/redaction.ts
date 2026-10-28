export function redactGitHubLogin(login?: string | null): string {
  if (!login) return "unknown";
  if (login.length <= 2) return "*".repeat(login.length);
  return `${login[0]}${"*".repeat(login.length - 2)}${login[login.length - 1]}`;
}
