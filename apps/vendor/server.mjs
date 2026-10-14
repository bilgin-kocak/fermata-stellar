// Fermata demo vendor: a TLS 1.2 HTTPS JSON API that TLSNotary (tlsn v0.1.0-alpha.15) can prove.
// tlsn at that tag supports TLS 1.2 with ECDHE-ECDSA-AES128-GCM-SHA256 on P-256 only (FACTS §12.4).
//
//   GET  /v1/quote?symbol=BTC-USD         → 200 { price, timestamp, source, symbol }
//   POST /v1/quote  {"symbol":"BTC-USD"}  → same
//
// Env:
//   PORT        default 8443 (binds 127.0.0.1; the certificate names vendor.fermata.test)
//   CHAOS       force one behaviour for every request: 500 | truncate | cut | hang
//   CHAOS_RATE  0..1, probability that a request misbehaves (500 or truncated JSON, 50/50)
//   CERTS_DIR   default ./certs (run ./gen-certs.sh once)
//
// Copied unchanged from Fermata `apps/vendor/server.mjs` @ d7cc642 (github.com/bilgin-kocak/fermata, MIT).
import https from 'node:https'
import fs from 'node:fs'
import { constants } from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const certs = process.env.CERTS_DIR ?? path.join(here, 'certs')
const port = Number(process.env.PORT ?? 8443)
const forced = process.env.CHAOS ?? ''
const chaosRate = Number(process.env.CHAOS_RATE ?? 0)
if (!['', '500', 'truncate', 'cut', 'hang'].includes(forced)) throw new Error(`unknown CHAOS=${forced}`)
if (!(chaosRate >= 0 && chaosRate <= 1)) throw new Error(`CHAOS_RATE must be in [0, 1], got ${process.env.CHAOS_RATE}`)

const prices = { 'BTC-USD': 64231.5, 'ETH-USD': 3120.25, 'SOL-USD': 142.8 }

function behaviour() {
  if (forced) return forced
  if (chaosRate > 0 && Math.random() < chaosRate) return Math.random() < 0.5 ? '500' : 'truncate'
  return 'ok'
}

const server = https.createServer(
  {
    key: fs.readFileSync(path.join(certs, 'vendor-key.pem')),
    cert: fs.readFileSync(path.join(certs, 'vendor.pem')),
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2',
    ciphers: 'ECDHE-ECDSA-AES128-GCM-SHA256',
    ecdhCurve: 'prime256v1',
    honorCipherOrder: true,
    secureOptions: constants.SSL_OP_NO_TICKET | constants.SSL_OP_NO_COMPRESSION | constants.SSL_OP_NO_RENEGOTIATION,
  },
  (req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const send = (status, body) => {
        res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), Connection: 'close' })
        res.end(body)
      }
      const url = new URL(req.url ?? '/', 'https://vendor.fermata.test')
      if (url.pathname !== '/v1/quote' || !['GET', 'POST'].includes(req.method ?? '')) {
        return send(404, JSON.stringify({ error: 'not found' }))
      }
      let symbol = url.searchParams.get('symbol') ?? 'BTC-USD'
      if (req.method === 'POST') {
        try {
          symbol = JSON.parse(Buffer.concat(chunks).toString()).symbol ?? symbol
        } catch {
          return send(400, JSON.stringify({ error: 'body must be JSON' }))
        }
      }
      const price = prices[symbol]
      if (price === undefined) return send(404, JSON.stringify({ error: `unknown symbol ${symbol}` }))
      const quote = JSON.stringify({ price, timestamp: Math.floor(Date.now() / 1000), source: 'fermata-demo-vendor', symbol })

      switch (behaviour()) {
        case '500':
          return send(500, JSON.stringify({ error: 'upstream exploded' }))
        case 'truncate': {
          // Complete HTTP message whose body is half a JSON document: malformed, but provable.
          const cut = quote.slice(0, Math.floor(quote.length / 2))
          return send(200, cut)
        }
        case 'cut':
          // Promise the full body, send 10 bytes, drop the connection.
          res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(quote), Connection: 'close' })
          res.write(quote.slice(0, 10))
          return req.socket.destroy()
        case 'hang':
          return // never answer: no transcript, only the on-chain timeout can refund
        default:
          return send(200, quote)
      }
    })
  },
)
server.listen(port, '127.0.0.1', () =>
  console.log(`vendor listening on https://127.0.0.1:${port} (chaos=${forced || (chaosRate ? `rate ${chaosRate}` : 'none')})`),
)
