//! Sessions (docs/session-escrow.md, phase 1: every call proved, k = 1). The attestor proves each
//! call of a session as it proves a held call, checks it against the agent's ticket and the
//! session on chain instead of a hold, keeps a book of the session's calls, and signs the batch
//! statements that settle them.
//!
//! New in this repository; Fermata has no sessions. The binding checks are the hold's (verify.rs)
//! with two changes. Check 3 (request) also needs the agent's ticket for call n, which signs
//! `chain(n) = sha256(chain(n − 1) ‖ requestHash)`: it is checked before anything is proved, so a
//! call no ticket covers never reaches the vendor. Check 5 (hold) becomes a check of the session:
//! open, this attestor its verifier, k = 1, and calls before the session's expiry.
//!
//! A call whose proving fails, or whose proof does not bind, is recorded as UNANSWERED: as with a
//! hold that gets no verdict, no proof means a refund.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, sync::Mutex};

use ed25519_dalek::SigningKey;
use fermata_verdict::{
    Domain, hex32,
    keys::account_address,
    session::{self as fs, Entry, Statement},
};

use crate::{
    chain::{ChainView, SESSION_OPEN, ServiceInfo, SessionInfo},
    hashes::{hex0x, keccak256, notary_key_hash, predicate_hash, request_hash, to_hex},
    predicate::Predicate,
    verify::{Check, SESSION_SKEW_SECS, VerifiedCall, VerifyError, decide},
};

/// Where sessions live: the session contract on a network (the domain of tickets and statements).
#[derive(Clone, Debug)]
pub struct SessionTarget {
    pub contract: [u8; 32],
    pub domain: Domain,
}

impl SessionTarget {
    pub fn new(network_passphrase: &str, contract: [u8; 32]) -> Self {
        Self {
            contract,
            domain: Domain::new(network_passphrase, contract),
        }
    }
}

/// One call of a session, as the book records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRecord {
    pub n: u32,
    #[serde(with = "hex32")]
    pub call_id: [u8; 32],
    #[serde(with = "hex32")]
    pub request_hash: [u8; 32],
    /// chain(n).
    #[serde(with = "hex32")]
    pub chain: [u8; 32],
    /// The agent's signature over ticket(n), hex.
    pub ticket: String,
    /// None while the call is being proved.
    pub entry: Option<Entry>,
}

fn fail<T>(check: Check, detail: impl Into<String>) -> Result<T, VerifyError> {
    Err(VerifyError {
        check,
        detail: detail.into(),
    })
}

fn unanswered() -> Entry {
    Entry::unanswered()
}

// ---------------------------------------------------------------------------------- the book

/// A refusal to record or sign that is not a binding check: a call out of order, a call already
/// recorded, a statement over calls the book does not have.
#[derive(Debug)]
pub struct BookError(pub String);

impl std::fmt::Display for BookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BookError {}

/// The calls this attestor recorded, per session, in memory and in `<dir>/<session id>.jsonl`
/// (one line per change, so a record is never rewritten). A call still being proved when the
/// attestor stopped had no proof: it is read back as UNANSWERED.
pub struct Books {
    dir: PathBuf,
    books: Mutex<HashMap<[u8; 32], BTreeMap<u32, CallRecord>>>,
}

impl Books {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            books: Mutex::default(),
        }
    }

    fn path(&self, session_id: &[u8; 32]) -> PathBuf {
        self.dir.join(format!("{}.jsonl", to_hex(session_id)))
    }

    async fn load(&self, session_id: &[u8; 32]) -> Result<BTreeMap<u32, CallRecord>> {
        let path = self.path(session_id);
        let mut book = BTreeMap::new();
        let text = match tokio::fs::read_to_string(&path).await {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(book),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let r: CallRecord = serde_json::from_str(line)
                .with_context(|| format!("{}: bad line {line:?}", path.display()))?;
            book.insert(r.n, r);
        }
        let stopped: Vec<u32> = book
            .values()
            .filter(|r| r.entry.is_none())
            .map(|r| r.n)
            .collect();
        for n in stopped {
            let r = book.get_mut(&n).expect("present");
            r.entry = Some(unanswered());
            append(&path, r).await?;
        }
        Ok(book)
    }

    /// Runs `f` on a session's book, loading it first if needed.
    async fn with<T>(
        &self,
        session_id: &[u8; 32],
        f: impl FnOnce(&mut BTreeMap<u32, CallRecord>) -> T,
    ) -> Result<T> {
        let mut books = self.books.lock().await;
        if !books.contains_key(session_id) {
            let book = self.load(session_id).await?;
            books.insert(*session_id, book);
        }
        Ok(f(books.get_mut(session_id).expect("loaded")))
    }

    /// chain(n − 1) for the next call n: the contract's chain when n − 1 calls are settled, else
    /// the book's record of call n − 1. Fails when call n − 1 is unknown or call n is not next.
    pub async fn prev_chain(
        &self,
        session_id: &[u8; 32],
        session: &SessionInfo,
        n: u32,
    ) -> Result<std::result::Result<[u8; 32], BookError>> {
        self.with(session_id, |book| prev_chain(book, session, n))
            .await
    }

    /// Records call n before it is proved. It must be the next call: after the book's last call,
    /// or after the contract's settled calls when the book has none past them.
    pub async fn reserve(
        &self,
        session_id: &[u8; 32],
        session: &SessionInfo,
        record: CallRecord,
    ) -> Result<std::result::Result<(), BookError>> {
        let path = self.path(session_id);
        let mut books = self.books.lock().await;
        if !books.contains_key(session_id) {
            let book = self.load(session_id).await?;
            books.insert(*session_id, book);
        }
        let book = books.get_mut(session_id).expect("loaded");
        if let Err(e) = prev_chain(book, session, record.n) {
            return Ok(Err(e));
        }
        tokio::fs::create_dir_all(&self.dir).await?;
        append(&path, &record).await?;
        book.insert(record.n, record);
        Ok(Ok(()))
    }

    /// Records the result of call n.
    pub async fn complete(
        &self,
        session_id: &[u8; 32],
        n: u32,
        entry: Entry,
    ) -> Result<CallRecord> {
        let path = self.path(session_id);
        let mut books = self.books.lock().await;
        let book = books
            .get_mut(session_id)
            .context("no book for this session")?;
        let r = book.get_mut(&n).context("call not reserved")?;
        anyhow::ensure!(r.entry.is_none(), "call {n} already has a result");
        r.entry = Some(entry);
        append(&path, r).await?;
        Ok(r.clone())
    }

    /// Every call the book has for a session, in order.
    pub async fn calls(&self, session_id: &[u8; 32]) -> Result<Vec<CallRecord>> {
        self.with(session_id, |book| book.values().cloned().collect())
            .await
    }
}

async fn append(path: &Path, record: &CallRecord) -> Result<()> {
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(&line).await?;
    file.sync_data().await?;
    Ok(())
}

fn prev_chain(
    book: &BTreeMap<u32, CallRecord>,
    session: &SessionInfo,
    n: u32,
) -> std::result::Result<[u8; 32], BookError> {
    if n == 0 || n > session.max_calls {
        return Err(BookError(format!(
            "call {n} is outside the session's {} calls",
            session.max_calls
        )));
    }
    if n <= session.settled {
        return Err(BookError(format!("call {n} is already settled")));
    }
    if book.contains_key(&n) {
        return Err(BookError(format!("call {n} was already attested")));
    }
    let last = book
        .keys()
        .next_back()
        .copied()
        .unwrap_or(0)
        .max(session.settled);
    if n != last + 1 {
        return Err(BookError(format!(
            "call {n} is not the next call ({})",
            last + 1
        )));
    }
    if n - 1 == session.settled {
        return Ok(session.chain);
    }
    book.get(&(n - 1))
        .map(|r| r.chain)
        .ok_or_else(|| BookError(format!("call {} is not in this attestor's book", n - 1)))
}

// ----------------------------------------------------------------------- admitting a call

/// A session call to prove (or to record as unanswered): the request, as for a hold, plus the
/// session, the call's number and the agent's ticket for it.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRequest {
    pub session_id: String,
    pub n: u32,
    /// The agent's signature over ticket(n), hex.
    pub ticket: String,
    pub method: String,
    /// The origin-form request target, e.g. `/v1/quote?symbol=BTC-USD`.
    pub target: String,
    pub body: Vec<u8>,
}

/// What the checks before proving established about a call.
#[derive(Clone, Debug)]
pub struct Admitted {
    pub session_id: [u8; 32],
    pub session: SessionInfo,
    pub service: ServiceInfo,
    pub n: u32,
    pub call_id: [u8; 32],
    pub request_hash: [u8; 32],
    pub chain: [u8; 32],
    pub ticket: [u8; 64],
    /// The last ledger time calls are taken: the session's deadline minus the settlement window.
    pub expires_at: u64,
}

impl Admitted {
    pub fn record(&self) -> CallRecord {
        CallRecord {
            n: self.n,
            call_id: self.call_id,
            request_hash: self.request_hash,
            chain: self.chain,
            ticket: to_hex(&self.ticket),
            entry: None,
        }
    }
}

/// Why a call is not admitted: a binding check (422) or the book's order (409).
#[derive(Debug)]
pub enum Refusal {
    Check(VerifyError),
    Book(BookError),
    Other(anyhow::Error),
}

impl From<VerifyError> for Refusal {
    fn from(e: VerifyError) -> Self {
        Self::Check(e)
    }
}

impl From<anyhow::Error> for Refusal {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

/// The checks before proving call n: the session is open, this attestor is its verifier, k = 1,
/// the chain time is before the session's expiry (`for_proving`; recording a call as unanswered
/// is allowed until the deadline), call n is the next one, and the agent's ticket for call n
/// signs the chain extended by this request's hash.
pub async fn admit<C: ChainView>(
    chain: &C,
    target: &SessionTarget,
    verifier: &[u8; 32],
    books: &Books,
    req: &CallRequest,
    for_proving: bool,
) -> Result<Admitted, Refusal> {
    let session_id = crate::hashes::parse_hex32(&req.session_id)?;
    let ticket: [u8; 64] = fermata_verdict::parse_hex::<64>(&req.ticket)
        .map_err(|e| anyhow::anyhow!("ticket: {e}"))?;
    let session = chain.session(target.contract, session_id).await?;
    if session.status != SESSION_OPEN {
        return Err(VerifyError {
            check: Check::Session,
            detail: if session.status == 0 {
                "no session with this id".into()
            } else {
                format!("session status {} is not Open", session.status)
            },
        }
        .into());
    }
    if &session.verifier != verifier {
        return Err(VerifyError {
            check: Check::Session,
            detail: format!(
                "the session's verifier is {}, not this attestor",
                account_address(&session.verifier)
            ),
        }
        .into());
    }
    if session.sample_k != 1 {
        return Err(VerifyError {
            check: Check::Session,
            detail: format!(
                "the session samples one call in {}; phase 1 proves every call (k = 1)",
                session.sample_k
            ),
        }
        .into());
    }
    let service = chain.service(session.service_id).await?;
    let expires_at = session
        .deadline
        .saturating_sub(u64::from(service.settlement_window));
    let now = chain.latest_timestamp().await?;
    let last = if for_proving {
        expires_at
    } else {
        session.deadline
    };
    if now > last {
        return Err(VerifyError {
            check: Check::Session,
            detail: format!("the session took calls until {last} (chain time {now})"),
        }
        .into());
    }
    let prev = match books.prev_chain(&session_id, &session, req.n).await? {
        Ok(c) => c,
        Err(e) => return Err(Refusal::Book(e)),
    };
    let request_hash = request_hash(&session.service_id, &req.method, &req.target, &req.body);
    let chain_n = fs::chain_next(&prev, &request_hash);
    if fs::verify_ticket(
        &session.ticket_key,
        &target.domain,
        &session_id,
        req.n,
        &chain_n,
        &ticket,
    )
    .is_err()
    {
        return Err(VerifyError {
            check: Check::Ticket,
            detail: format!(
                "the agent's ticket for call {} does not cover {} {} after chain {}",
                req.n,
                req.method,
                req.target,
                to_hex(&prev)
            ),
        }
        .into());
    }
    Ok(Admitted {
        call_id: fs::call_id(&target.contract, &session_id, req.n),
        session_id,
        session,
        service,
        n: req.n,
        request_hash,
        chain: chain_n,
        ticket,
        expires_at,
    })
}

// --------------------------------------------------------------- checking a proved call

/// Binding checks 1–7 for a proved session call, in the hold's order (verify.rs): notary, origin,
/// request (the request the ticket covers), predicate, session, call header (call_id(n)) and TLS
/// session time within [opened_at − 60 s, deadline].
pub fn check_session_bindings(
    v: &VerifiedCall,
    a: &Admitted,
    predicate_bytes: &[u8],
    now: u64,
) -> Result<(), VerifyError> {
    // 1. notary
    if notary_key_hash(&v.notary_key) != a.service.notary_key_hash {
        return fail(
            Check::Notary,
            format!(
                "notary key {} is not the service's notary",
                to_hex(&v.notary_key)
            ),
        );
    }
    // 2. origin
    let origin = v.origin()?;
    if origin.hash() != a.service.origin_hash {
        return fail(
            Check::Origin,
            format!("{} is not the registered origin", origin.canonical()),
        );
    }
    // 3. request
    let rh = request_hash(
        &a.session.service_id,
        &v.request.method,
        &v.request.target,
        &v.request.body,
    );
    if rh != a.request_hash {
        return fail(
            Check::Request,
            format!(
                "{} {} hashes to {}; the ticket covers {}",
                v.request.method,
                v.request.target,
                to_hex(&rh),
                to_hex(&a.request_hash)
            ),
        );
    }
    // 4. predicate
    if predicate_hash(predicate_bytes) != a.session.predicate_hash {
        return fail(
            Check::Predicate,
            "predicate does not hash to the session's predicateHash",
        );
    }
    // 5. session
    if a.session.status != SESSION_OPEN || now > a.session.deadline {
        return fail(
            Check::Session,
            format!(
                "the session is not open, or its deadline {} passed (chain time {now})",
                a.session.deadline
            ),
        );
    }
    // 6. call
    match v.call_header() {
        Some(h) if h.trim().eq_ignore_ascii_case(&hex0x(&a.call_id)) => {}
        other => {
            return fail(
                Check::Call,
                format!(
                    "X-Fermata-Call {other:?} is not call {} of the session ({})",
                    a.n,
                    hex0x(&a.call_id)
                ),
            );
        }
    }
    // 7. time
    if v.time + SESSION_SKEW_SECS < a.session.opened_at || v.time > a.session.deadline {
        return fail(
            Check::Time,
            format!(
                "TLS session at {} outside the session [{}, {}]",
                v.time, a.session.opened_at, a.session.deadline
            ),
        );
    }
    Ok(())
}

/// A proved call's entry: the checks, then the predicate. DELIVERED or FAILED, with the
/// presentation's and the response's hashes.
pub fn decide_call(
    v: &VerifiedCall,
    a: &Admitted,
    predicate_bytes: &[u8],
    now: u64,
) -> Result<(Entry, Vec<String>), VerifyError> {
    check_session_bindings(v, a, predicate_bytes, now)?;
    let predicate: Predicate =
        serde_json::from_slice(predicate_bytes).map_err(|e| VerifyError {
            check: Check::Predicate,
            detail: format!("predicate JSON: {e}"),
        })?;
    let (outcome, failures) = decide(v, &predicate);
    let entry = Entry::proved(
        outcome == fermata_verdict::OUTCOME_DELIVERED,
        v.presentation_hash,
        keccak256(&v.received),
    );
    Ok((entry, failures))
}

// ------------------------------------------------------------------------------ statements

/// A signed batch statement and everything `settle_batch` takes with it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedStatement {
    pub statement: Statement,
    /// The 288 bytes the session contract rebuilds and verifies (hex).
    pub message: String,
    /// The verifier's signature over `message` (hex): `settle_batch`'s `statement`.
    pub signature: String,
    pub from: u32,
    pub to: u32,
    /// The calls' request hashes, in order (`settle_batch` takes them concatenated).
    pub request_hashes: Vec<String>,
    /// The calls' entries, in order (`settle_batch` takes their bytes concatenated).
    pub entries: Vec<Entry>,
    /// The agent's ticket for call `to` (hex): `settle_batch`'s `ticket`.
    pub ticket: String,
    pub signer: String,
}

/// Signs the statement for calls `settled + 1` through `to` from the book: every call recorded
/// with a result, chained from the contract's `chain(settled)`, no more than B calls, before the
/// deadline, for a session with k = 1 whose verifier is `key`.
pub async fn sign_statement<C: ChainView>(
    chain: &C,
    target: &SessionTarget,
    key: &SigningKey,
    books: &Books,
    session_id: [u8; 32],
    to: u32,
) -> Result<SignedStatement, Refusal> {
    let session = chain.session(target.contract, session_id).await?;
    let public = key.verifying_key().to_bytes();
    if session.status != SESSION_OPEN {
        return Err(Refusal::Book(BookError(format!(
            "the session is not open (status {})",
            session.status
        ))));
    }
    if session.verifier != public || session.sample_k != 1 {
        return Err(Refusal::Book(BookError(
            "this attestor signs statements only for sessions it verifies, with k = 1".into(),
        )));
    }
    let now = chain.latest_timestamp().await?;
    if now > session.deadline {
        return Err(Refusal::Book(BookError(format!(
            "the session's deadline {} has passed (chain time {now})",
            session.deadline
        ))));
    }
    let from = session.settled;
    if to <= from || to > session.max_calls || to - from > session.batch_size {
        return Err(Refusal::Book(BookError(format!(
            "a batch must settle calls {} to at most {} (B = {}), not to {to}",
            from + 1,
            (from + session.batch_size).min(session.max_calls),
            session.batch_size
        ))));
    }
    let calls = books.calls(&session_id).await?;
    let by_n: BTreeMap<u32, &CallRecord> = calls.iter().map(|r| (r.n, r)).collect();
    let mut prev = session.chain;
    let mut request_hashes = Vec::new();
    let mut entries = Vec::new();
    for n in from + 1..=to {
        let Some(r) = by_n.get(&n) else {
            return Err(Refusal::Book(BookError(format!(
                "call {n} is not in this attestor's book"
            ))));
        };
        let Some(entry) = r.entry else {
            return Err(Refusal::Book(BookError(format!(
                "call {n} is still being proved"
            ))));
        };
        if fs::chain_next(&prev, &r.request_hash) != r.chain {
            return Err(Refusal::Book(BookError(format!(
                "the book's call {n} does not extend the contract's chain"
            ))));
        }
        prev = r.chain;
        request_hashes.push(to_hex(&r.request_hash));
        entries.push(entry);
    }
    let statement = Statement {
        session_id,
        service_id: session.service_id,
        predicate_hash: session.predicate_hash,
        from,
        to,
        chain: prev,
        seed: [0; 32],
        entries_hash: fs::entries_hash(&entries),
    };
    Ok(SignedStatement {
        message: to_hex(&fs::statement_message(&target.domain, &statement)),
        signature: to_hex(&fs::sign_statement(key, &target.domain, &statement)),
        from,
        to,
        request_hashes,
        entries,
        ticket: by_n[&to].ticket.clone(),
        signer: account_address(&public),
        statement,
    })
}

#[cfg(test)]
mod tests;
