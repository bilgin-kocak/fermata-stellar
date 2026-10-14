// The Channels client against a stub of the service's documented responses.
import { describe, expect, it } from 'vitest'
import { ChannelsError, submitThroughChannels } from '../src/index.ts'

function stub(status: number, body: unknown) {
  const calls: { url: string; init: RequestInit }[] = []
  const fetch = (async (url: string, init: RequestInit) => {
    calls.push({ url, init })
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
  }) as unknown as typeof globalThis.fetch
  return { fetch, calls }
}

describe('submitThroughChannels', () => {
  it('posts the function and its authorization, and returns the transaction hash', async () => {
    const s = stub(200, { success: true, data: { transactionId: 't1', hash: 'ab'.repeat(32), status: 'confirmed' } })
    const res = await submitThroughChannels({ baseUrl: 'https://channels.example/testnet/', apiKey: 'k', fetch: s.fetch }, 'RlVOQw==', ['QVVUSA=='])
    expect(res).toEqual({ transactionId: 't1', hash: 'ab'.repeat(32), status: 'confirmed' })
    expect(s.calls[0]!.url).toBe('https://channels.example/testnet/')
    expect(JSON.parse(s.calls[0]!.init.body as string)).toEqual({ params: { func: 'RlVOQw==', auth: ['QVVUSA=='] } })
    expect((s.calls[0]!.init.headers as Record<string, string>).authorization).toBe('Bearer k')
  })

  it("routes through a self-hosted Relayer's plugin endpoint", async () => {
    const s = stub(200, { success: true, data: { transactionId: 't2', hash: 'cd'.repeat(32), status: 'confirmed' } })
    await submitThroughChannels({ baseUrl: 'http://localhost:8080', apiKey: 'k', pluginId: 'channels', fetch: s.fetch }, 'Rg==', [])
    expect(s.calls[0]!.url).toBe('http://localhost:8080/api/v1/plugins/channels/call')
  })

  it('throws on a refusal or a malformed answer', async () => {
    await expect(submitThroughChannels({ baseUrl: 'https://c', apiKey: 'k', fetch: stub(200, { success: false, error: 'simulation failed' }).fetch }, 'Rg==', [])).rejects.toThrow(
      /simulation failed/,
    )
    await expect(submitThroughChannels({ baseUrl: 'https://c', apiKey: 'k', fetch: stub(502, { oops: 1 }).fetch }, 'Rg==', [])).rejects.toBeInstanceOf(ChannelsError)
  })
})
