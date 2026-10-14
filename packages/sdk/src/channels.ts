// OpenZeppelin's Channels service: submits a Soroban invocation given as a host function and its
// signed authorization entries, from a pool of channel accounts, with the fee paid by the service's
// fund account. It runs as an OpenZeppelin Relayer plugin, hosted (an API key from a web form) or
// self-hosted. This is a minimal client for the one request Fermata needs, written against the
// plugin's documented API (`@openzeppelin/relayer-plugin-channels` 0.21.0, MIT, README "Submit with
// Function and Auth" and `src/client/channels-client.ts`): POST `{ params: { func, auth } }`,
// answered with `{ success, data: { transactionId, hash, status }, error }`.

export type ChannelsConfig = {
  /** The managed service (`https://channels.openzeppelin.com/testnet`) or a Relayer's base URL. */
  baseUrl: string
  apiKey: string
  /** For a self-hosted Relayer: the plugin id; requests go to `/api/v1/plugins/<id>/call`. */
  pluginId?: string
  timeoutMs?: number
  fetch?: typeof globalThis.fetch
}

export type ChannelsResult = { transactionId: string | null; hash: string | null; status: string | null }

export class ChannelsError extends Error {
  constructor(
    message: string,
    readonly detail?: unknown,
  ) {
    super(message)
    this.name = 'ChannelsError'
  }
}

/** Submits `func` (HostFunction XDR, base64) with its signed `auth` entries and waits for the result. */
export async function submitThroughChannels(cfg: ChannelsConfig, func: string, auth: string[]): Promise<ChannelsResult> {
  const base = cfg.baseUrl.replace(/\/+$/, '')
  const url = cfg.pluginId ? `${base}/api/v1/plugins/${encodeURIComponent(cfg.pluginId)}/call` : `${base}/`
  const headers: Record<string, string> = { 'content-type': 'application/json', authorization: `Bearer ${cfg.apiKey}` }
  if (cfg.pluginId) headers['x-api-key'] = cfg.apiKey
  const res = await (cfg.fetch ?? fetch)(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ params: { func, auth } }),
    signal: AbortSignal.timeout(cfg.timeoutMs ?? 60_000),
  })
  const body = (await res.json().catch(() => undefined)) as
    | { success?: boolean; data?: Partial<ChannelsResult>; error?: string }
    | undefined
  if (!body || typeof body !== 'object' || body.success === undefined) {
    throw new ChannelsError(`Channels answered HTTP ${res.status} without a result`)
  }
  if (!body.success) throw new ChannelsError(`Channels refused the transaction: ${body.error ?? 'no reason given'}`, body.data)
  return { transactionId: body.data?.transactionId ?? null, hash: body.data?.hash ?? null, status: body.data?.status ?? null }
}
