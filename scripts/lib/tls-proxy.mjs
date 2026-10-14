// HTTPS in front of a local network's RPC, for the libraries that refuse a plain-HTTP RPC URL
// (Stellar's MPP Charge sets no `allowHttp`). Development and CI only: it forwards every request to
// TARGET unchanged.
//
//   node scripts/lib/tls-proxy.mjs LISTEN_PORT TARGET KEY_PEM CERT_PEM
//   node scripts/lib/tls-proxy.mjs 7443 http://127.0.0.1:8000 key.pem cert.pem
import { readFileSync } from 'node:fs'
import { request } from 'node:http'
import { createServer } from 'node:https'

const [port, target, key, cert] = process.argv.slice(2)
if (!port || !target || !key || !cert) {
  console.error('usage: tls-proxy.mjs LISTEN_PORT TARGET KEY_PEM CERT_PEM')
  process.exit(64)
}
const upstream = new URL(target)

createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (req, res) => {
  const forward = request(
    new URL(req.url ?? '/', upstream),
    { method: req.method, headers: { ...req.headers, host: upstream.host } },
    (r) => {
      res.writeHead(r.statusCode ?? 502, r.headers)
      r.pipe(res)
    },
  )
  forward.on('error', (e) => {
    res.writeHead(502, { 'content-type': 'text/plain' })
    res.end(`proxy: ${e.message}`)
  })
  req.pipe(forward)
}).listen(Number(port), '127.0.0.1', () => console.log(`https://127.0.0.1:${port} -> ${target}`))
