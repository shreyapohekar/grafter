export type TokenPoolQuota = {
  rate_limit_limit?: number | null;
  rate_limit_remaining?: number | null;
  rate_limit_reset?: number | null;
  pool_rate_limit_limit?: number | null;
  pool_rate_limit_remaining?: number | null;
  pool_rate_limit_reset?: number | null;
  pool_tokens_checked?: number;
  token_pool_size?: number | null;
  pool_accounts?: { account: string; limit: number; remaining: number; reset?: number | null }[];
};

export default function GitHubQuota({ quota }: { quota: TokenPoolQuota }) {
  const combined = quota.pool_rate_limit_limit != null && quota.pool_rate_limit_remaining != null;
  const size = quota.token_pool_size ?? 1;
  const partial = combined && (quota.pool_tokens_checked ?? 0) < size;
  const reset = combined ? quota.pool_rate_limit_reset : quota.rate_limit_reset;
  const minutes = reset ? Math.max(0, Math.round((reset * 1000 - Date.now()) / 60000)) : 0;
  return (
    <span title={quota.pool_accounts?.map((account) =>
      `${redactGitHubLogin(account.account)}: ${account.remaining}/${account.limit} requests remaining`
    ).join("\n")}>
      {combined
        ? `GitHub API pool: ${quota.pool_rate_limit_remaining}/${quota.pool_rate_limit_limit} requests remaining across ${size} token${size === 1 ? "" : "s"}`
        : quota.rate_limit_remaining != null && quota.rate_limit_limit != null
        ? `GitHub API (active token): ${quota.rate_limit_remaining}/${quota.rate_limit_limit} requests remaining`
        : "GitHub API pool: checking quota..."}
      {partial && ` · partial quota (${quota.pool_tokens_checked}/${size} tokens checked)`}
      {combined && size > 1 && quota.rate_limit_remaining != null && quota.rate_limit_limit != null
        && ` · active token: ${quota.rate_limit_remaining}/${quota.rate_limit_limit}`}
      {reset ? reset * 1000 <= Date.now()
        ? " · quota reset due; refreshing quota"
        : ` · next reset ${new Date(reset * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}${minutes > 0 ? ` (in ${minutes}m)` : ""}` : ""}
    </span>
  );
}
import { redactGitHubLogin } from "./redaction";
