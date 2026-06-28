//! The per-direction streaming HTTP/1.1 framer: it buffers and rewrites the header, then forwards the
//! body as a zero-copy slice of the fed input via [`feed`](HttpFraming::feed). Built on the parent
//! module's authority parser.

use std::net::SocketAddrV4;

use super::{Authority, parse_authority, strip_prefix_ignore_ascii_case};

/// CRLF, the HTTP line terminator.
const CRLF: &[u8] = b"\r\n";

/// The blank line that ends a header block.
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// The header-block byte cap: a header that has not terminated by this point is refused, so a peer
/// can't grow the owner's buffer unbounded. The proxy's receive buffer must EXCEED this (a const-assert
/// there) or the over-cap refusal can't fire before the buffer fills and the reader livelocks.
pub(crate) const MAX_HEADER: usize = 2 * 1024;

/// The unterminated-line guard for a single chunk-size line (`1a3\r\n`, plus any chunk extensions).
const MAX_CHUNK_LINE: usize = 256;

/// The unterminated-line guard for a single trailer field line — looser than a chunk-size line, since
/// trailers carry header-like field values.
const MAX_TRAILER_LINE: usize = 1024;

/// Which side of the splice a framer parses: the start line differs (request-line vs status-line),
/// and only a response can be close-delimited.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Request,
    Response,
}

/// The body framing the header determined — what `feed` streams after the header. `Header` doubles as
/// "no body: the message ends at the blank line".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Header,
    BodyContentLength,
    BodyChunked,
    /// After the zero-size chunk: consume trailer field lines until the blank line.
    BodyChunkedTrailers,
    BodyCloseDelimited,
}

/// A malformed or over-cap message — the proxy maps any variant to drop-and-close.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FramingError {
    /// A header block that never terminated within [`MAX_HEADER`] bytes.
    HeaderTooLong,
    /// A `Content-Length` value that isn't a bare non-negative integer.
    MalformedContentLength,
    /// A chunk-size line that isn't a hex integer.
    MalformedChunkSize,
    /// A chunk-size line that never terminated within [`MAX_CHUNK_LINE`] bytes.
    ChunkLineTooLong,
    /// A trailer field line that never terminated within [`MAX_TRAILER_LINE`] bytes.
    TrailerLineTooLong,
}

/// One [`feed`](HttpFraming::feed) call's forwardable output: the rewritten `header` (a view into the
/// framer's scratch; empty while a body streams across feeds), the `body` (a zero-copy slice of the fed
/// input; possibly empty), and `consumed` — how many fed bytes to drop. `consumed == 0` means an
/// incomplete header: read more and feed again. `authority` is the authority header this message carried
/// (with the endpoint it named, *before* the rewrite), reported on the feed that completes the header; the
/// DIAL proxy acts on `Application-URL` (to learn and re-learn the device's REST target). `None` when the
/// header carried no rewritable authority.
pub(crate) struct Framed<'a> {
    pub(crate) header: &'a [u8],
    pub(crate) body: &'a [u8],
    pub(crate) consumed: usize,
    pub(crate) authority: Option<AuthorityHeader>,
}

/// Per-direction incremental HTTP/1.1 framing with an authority-header rewrite. It buffers only the
/// header — copied into a scratch so it can be rewritten — and forwards the body as a zero-copy slice
/// of the fed input. The [`RewritePolicy`] is fixed for the framer's lifetime (the owner's per-direction
/// targets don't change over a connection), so it is stored at construction rather than passed per feed.
pub(crate) struct HttpFraming {
    kind: Kind,
    rewrite: RewritePolicy,
    phase: Phase,
    header: Vec<u8>,
    body_remaining: usize,
    chunk_remaining: usize,
}

impl HttpFraming {
    /// A framer for one direction, rewriting authority headers per `rewrite`.
    pub(crate) fn new(kind: Kind, rewrite: RewritePolicy) -> Self {
        Self {
            kind,
            rewrite,
            phase: Phase::Header,
            header: Vec::new(),
            body_remaining: 0,
            chunk_remaining: 0,
        }
    }

    /// Feed a contiguous view of the owner's buffered bytes; returns the forwardable [`Framed`]. Each
    /// call yields at most one message's header plus as much of its body as arrived; the owner forwards
    /// `header` then `body`, drops `consumed` bytes, and feeds again until `consumed` is 0 (an
    /// incomplete header — read more). `header` borrows the framer's scratch and `body` the input, so
    /// the owner forwards both before advancing past `consumed`.
    ///
    /// Each authority header (`Host` on requests, `Application-URL` / `Location` on responses) is
    /// rewritten per the framer's [`RewritePolicy`] — a per-header target, so one direction can send,
    /// say, `Application-URL` and `Location` to different listeners.
    ///
    /// # Errors
    /// A malformed or over-cap message: see [`FramingError`].
    pub(crate) fn feed<'a>(&'a mut self, input: &'a [u8]) -> Result<Framed<'a>, FramingError> {
        let mut pos = 0;
        let mut header_complete = false;
        let mut authority = None;
        if matches!(self.phase, Phase::Header) {
            let Some(end) = find_header_end(input) else {
                if input.len() > MAX_HEADER {
                    return Err(FramingError::HeaderTooLong);
                }
                return Ok(Framed {
                    header: &[],
                    body: &[],
                    consumed: 0,
                    authority: None,
                }); // incomplete: read more
            };
            authority = self.scan_and_rewrite_header(&input[..end])?;
            pos = end;
            header_complete = true;
        }
        // Forward as much of the body as arrived (a zero-copy slice of `input`), stopping at the message
        // boundary, the end of the input, or an incomplete chunk/trailer line (left for the next feed).
        let body_start = pos;
        loop {
            if pos >= input.len() {
                break;
            }
            match self.phase {
                Phase::Header => break, // the next message starts here — one message per feed
                Phase::BodyContentLength => {
                    let take = self.body_remaining.min(input.len() - pos);
                    pos += take;
                    self.body_remaining -= take;
                    if self.body_remaining == 0 {
                        self.phase = Phase::Header;
                    }
                    break; // a Content-Length body is one contiguous run
                }
                Phase::BodyCloseDelimited => {
                    pos = input.len(); // forward all; the message ends at EOF (the owner's signal)
                    break;
                }
                Phase::BodyChunked if self.chunk_remaining > 0 => {
                    // Forwarding the current chunk's DATA(+CRLF), opaquely.
                    let take = self.chunk_remaining.min(input.len() - pos);
                    pos += take;
                    self.chunk_remaining -= take;
                    if self.chunk_remaining > 0 {
                        break; // ran out mid-chunk
                    }
                }
                Phase::BodyChunked => {
                    // At a chunk boundary: parse the next chunk-size line.
                    let Some(rel) = find_crlf(&input[pos..]) else {
                        if input.len() - pos > MAX_CHUNK_LINE {
                            return Err(FramingError::ChunkLineTooLong);
                        }
                        break; // incomplete chunk-size line
                    };
                    let size = parse_chunk_size(&input[pos..pos + rel])?;
                    pos += rel + CRLF.len();
                    if size == 0 {
                        self.phase = Phase::BodyChunkedTrailers;
                    } else {
                        self.chunk_remaining = size + CRLF.len(); // chunk DATA + its terminating CRLF
                    }
                }
                Phase::BodyChunkedTrailers => {
                    // Consume trailer field lines opaquely until the blank line ends the body.
                    let Some(rel) = find_crlf(&input[pos..]) else {
                        if input.len() - pos > MAX_TRAILER_LINE {
                            return Err(FramingError::TrailerLineTooLong);
                        }
                        break; // incomplete trailer line
                    };
                    let blank = rel == 0;
                    pos += rel + CRLF.len();
                    if blank {
                        self.phase = Phase::Header;
                    }
                }
            }
        }
        // Take the scratch borrow only now, after the loop is done mutating `self`.
        Ok(Framed {
            header: if header_complete { &self.header } else { &[] },
            body: &input[body_start..pos],
            consumed: pos,
            authority,
        })
    }

    /// Rewrite the authority headers of `block` (a complete header block ending in the blank line) into
    /// `self.header`, and set the body phase from its framing. Transforms on copy — each line is
    /// inspected and written to the scratch in one pass, so there is no in-place splice to re-offset.
    ///
    /// # Errors
    /// [`FramingError::MalformedContentLength`] for an unparseable `Content-Length`.
    fn scan_and_rewrite_header(
        &mut self,
        block: &[u8],
    ) -> Result<Option<AuthorityHeader>, FramingError> {
        self.header.clear();
        let mut content_length = None;
        let mut chunked = false;
        let mut authority = None;
        let mut status = 0;
        let mut pos = 0;
        let mut first = true;
        while pos < block.len() {
            let line_end = find_crlf(&block[pos..]).map_or(block.len(), |i| pos + i);
            let line = &block[pos..line_end];
            if first {
                if matches!(self.kind, Kind::Response) {
                    status = parse_status_code(line);
                }
                self.copy_line(line);
                first = false;
            } else if let Some(found) =
                self.inspect_and_emit(line, &mut content_length, &mut chunked)?
            {
                authority = Some(found);
            }
            pos = line_end + CRLF.len();
        }
        self.set_body_phase(status, content_length, chunked);
        Ok(authority)
    }

    /// Detect the framing headers (`Content-Length` / `Transfer-Encoding`), rewrite a `Host` /
    /// `Application-URL` / `Location` authority, and emit the (possibly rewritten) line to the scratch.
    fn inspect_and_emit(
        &mut self,
        line: &[u8],
        content_length: &mut Option<usize>,
        chunked: &mut bool,
    ) -> Result<Option<AuthorityHeader>, FramingError> {
        if let Some(value) = strip_prefix_ignore_ascii_case(line, b"Content-Length:") {
            *content_length = Some(parse_content_length(value)?);
            self.copy_line(line);
            return Ok(None);
        }
        if let Some(value) = strip_prefix_ignore_ascii_case(line, b"Transfer-Encoding:") {
            *chunked |= value_has_chunked(value);
            self.copy_line(line);
            return Ok(None);
        }
        if let Some((value_off, found, header)) = rewritable_authority(line) {
            // Rewrite to wherever the policy points this header, but report the header either way so the
            // owner learns the endpoint it named (it acts on `Application-URL` only).
            if let Some(repl) = self.rewrite.target(header) {
                let auth_start = value_off + found.offset;
                self.header.extend_from_slice(&line[..auth_start]);
                append_authority(&mut self.header, repl);
                self.header
                    .extend_from_slice(&line[auth_start + found.len..]);
                self.header.extend_from_slice(CRLF);
            } else {
                self.copy_line(line);
            }
            return Ok(Some(header));
        }
        self.copy_line(line);
        Ok(None)
    }

    /// Append `line` and its CRLF to the scratch verbatim.
    fn copy_line(&mut self, line: &[u8]) {
        self.header.extend_from_slice(line);
        self.header.extend_from_slice(CRLF);
    }

    /// Set the body phase from what the header scan found (RFC 7230 §3.3.3 + status-line awareness): a
    /// `1xx`/`204`/`304` response is bodyless regardless of headers; else chunked, then a
    /// `Content-Length` run, else — a request is bodyless, a response is close-delimited (until EOF).
    fn set_body_phase(&mut self, status: u16, content_length: Option<usize>, chunked: bool) {
        self.body_remaining = 0;
        self.chunk_remaining = 0;
        let bodyless_status =
            matches!(self.kind, Kind::Response) && matches!(status, 100..=199 | 204 | 304);
        self.phase = if bodyless_status {
            Phase::Header
        } else if chunked {
            Phase::BodyChunked
        } else if let Some(n) = content_length {
            if n == 0 {
                Phase::Header
            } else {
                self.body_remaining = n;
                Phase::BodyContentLength
            }
        } else {
            match self.kind {
                Kind::Request => Phase::Header,
                Kind::Response => Phase::BodyCloseDelimited,
            }
        };
    }
}

/// The length of the header block in `input` (up to and including the terminating blank line), or
/// `None` if the blank line has not arrived yet.
fn find_header_end(input: &[u8]) -> Option<usize> {
    input
        .windows(HEADER_TERMINATOR.len())
        .position(|w| w == HEADER_TERMINATOR)
        .map(|i| i + HEADER_TERMINATOR.len())
}

/// Parse a chunk-size line's hex length, dropping any `;`-delimited chunk extensions.
fn parse_chunk_size(line: &[u8]) -> Result<usize, FramingError> {
    let hex = match line.iter().position(|&b| b == b';') {
        Some(semi) => &line[..semi],
        None => line,
    };
    let text =
        std::str::from_utf8(hex.trim_ascii()).map_err(|_| FramingError::MalformedChunkSize)?;
    usize::from_str_radix(text, 16).map_err(|_| FramingError::MalformedChunkSize)
}

/// The byte offset of the first CRLF in `s`, or `None`.
fn find_crlf(s: &[u8]) -> Option<usize> {
    s.windows(2).position(|w| w == CRLF)
}

/// The status code from a response start line (`HTTP/1.1 200 OK` → 200), or 0 if unparseable — 0 is no
/// known bodyless status, so it falls through to the header-driven framing.
fn parse_status_code(line: &[u8]) -> u16 {
    line.split(|&b| b == b' ')
        .nth(1)
        .and_then(|field| std::str::from_utf8(field).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Parse a `Content-Length` value: surrounding whitespace (RFC 7230 OWS) is tolerated, but the rest
/// must be a bare integer — `12abc` is rejected, not truncated to 12.
fn parse_content_length(value: &[u8]) -> Result<usize, FramingError> {
    std::str::from_utf8(value.trim_ascii())
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or(FramingError::MalformedContentLength)
}

/// Whether a `Transfer-Encoding` value's coding list contains `chunked` (case-insensitive), e.g.
/// `gzip, chunked`.
fn value_has_chunked(value: &[u8]) -> bool {
    value
        .split(|&b| b == b',')
        .any(|coding| coding.trim_ascii().eq_ignore_ascii_case(b"chunked"))
}

/// Which authority-bearing header a line is, carrying the endpoint it named — so the framer rewrites it
/// and reports it, and the owner can act on `ApplicationUrl` alone (the DIAL REST base).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum AuthorityHeader {
    Host(SocketAddrV4),
    ApplicationUrl(SocketAddrV4),
    Location(SocketAddrV4),
}

/// Where a framer rewrites each authority header to — one optional target per [`AuthorityHeader`] kind,
/// `None` leaving that kind unchanged. The owner picks the targets (the DIAL proxy points `Host` at the
/// device, `Application-URL` at its REST listener, `Location` at the connection's own listener).
#[derive(Clone, Copy)]
pub(crate) struct RewritePolicy {
    pub(crate) host: Option<SocketAddrV4>,
    pub(crate) application_url: Option<SocketAddrV4>,
    pub(crate) location: Option<SocketAddrV4>,
}

impl RewritePolicy {
    /// The address `header` should be rewritten to under this policy, or `None` to leave it unchanged.
    fn target(&self, header: AuthorityHeader) -> Option<SocketAddrV4> {
        match header {
            AuthorityHeader::Host(_) => self.host,
            AuthorityHeader::ApplicationUrl(_) => self.application_url,
            AuthorityHeader::Location(_) => self.location,
        }
    }
}

/// If `line` is a `Host` / `Application-URL` / `Location` header, parse its authority — returning the
/// value's offset within `line`, the [`Authority`] (the span to rewrite, whose own offset is relative to
/// that value), and the header it was (carrying the endpoint it named).
fn rewritable_authority(line: &[u8]) -> Option<(usize, Authority, AuthorityHeader)> {
    let (value, bare, wrap): (&[u8], bool, fn(SocketAddrV4) -> AuthorityHeader) =
        if let Some(rest) = strip_prefix_ignore_ascii_case(line, b"Host:") {
            (rest, true, AuthorityHeader::Host)
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(line, b"Application-URL:") {
            (rest, false, AuthorityHeader::ApplicationUrl)
        } else if let Some(rest) = strip_prefix_ignore_ascii_case(line, b"Location:") {
            (rest, false, AuthorityHeader::Location)
        } else {
            return None;
        };
    let trimmed = value.trim_ascii_start();
    let value_off = line.len() - trimmed.len();
    let found = parse_authority(trimmed, bare)?;
    let header = wrap(found.endpoint);
    Some((value_off, found, header))
}

/// Append `addr` as `host:port` text — the IPv4 [`SocketAddrV4`] `Display` form.
fn append_authority(buf: &mut Vec<u8>, addr: SocketAddrV4) {
    use std::io::Write;
    write!(buf, "{addr}").expect("writing to a Vec is infallible");
}

#[cfg(test)]
mod tests {
    use super::*;

    impl RewritePolicy {
        /// A no-op policy — every authority header passes through unchanged. Tests only; the proxy
        /// always frames with a live policy.
        pub(crate) const NONE: Self = Self {
            host: None,
            application_url: None,
            location: None,
        };
    }

    /// A rewrite policy that sends every authority header to `repl`.
    fn rewrite_all(repl: SocketAddrV4) -> RewritePolicy {
        RewritePolicy {
            host: Some(repl),
            application_url: Some(repl),
            location: Some(repl),
        }
    }

    #[test]
    fn copies_a_header_verbatim_when_nothing_rewrites() {
        let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
        f.scan_and_rewrite_header(b"GET / HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n")
            .unwrap();
        assert_eq!(f.header, b"GET / HTTP/1.1\r\nHost: 10.0.0.1:80\r\n\r\n");
        assert_eq!(f.phase, Phase::Header); // a GET with no body framing is bodyless
    }

    #[test]
    fn rewrites_the_host_authority_on_a_request() {
        let repl: SocketAddrV4 = "10.1.3.80:36866".parse().unwrap();
        let mut f = HttpFraming::new(Kind::Request, rewrite_all(repl));
        f.scan_and_rewrite_header(b"GET /apps/YouTube HTTP/1.1\r\nHost: 10.0.0.1:8080\r\n\r\n")
            .unwrap();
        assert_eq!(
            f.header,
            b"GET /apps/YouTube HTTP/1.1\r\nHost: 10.1.3.80:36866\r\n\r\n"
        );
    }

    #[test]
    fn reports_the_application_url_endpoint_while_rewriting_it() {
        let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
        let mut f = HttpFraming::new(Kind::Response, rewrite_all(repl));
        let framed = f
            .feed(
                b"HTTP/1.1 200 OK\r\nApplication-URL: http://10.0.0.7:8008/apps\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
        // The owner learns the device's REST base (to dial it) even as the header is rewritten to the proxy.
        assert_eq!(
            framed.authority,
            Some(AuthorityHeader::ApplicationUrl(
                "10.0.0.7:8008".parse().unwrap()
            ))
        );
        assert_eq!(
            framed.header,
            &b"HTTP/1.1 200 OK\r\nApplication-URL: http://10.1.1.5:44747/apps\r\nContent-Length: 0\r\n\r\n"[..]
        );
        // A Location reports as its own variant (a launched-instance child URL), which the owner —
        // acting on Application-URL only — ignores.
        let mut g = HttpFraming::new(Kind::Response, rewrite_all(repl));
        let framed = g
            .feed(
                b"HTTP/1.1 201 Created\r\nLocation: http://10.0.0.7:8008/apps/X/run\r\nContent-Length: 0\r\n\r\n",
            )
            .unwrap();
        assert!(matches!(
            framed.authority,
            Some(AuthorityHeader::Location(_))
        ));
    }

    #[test]
    fn rewrites_location_in_a_chunked_201() {
        let repl: SocketAddrV4 = "10.1.1.5:44747".parse().unwrap();
        let mut f = HttpFraming::new(Kind::Response, rewrite_all(repl));
        f.scan_and_rewrite_header(
            b"HTTP/1.1 201 Created\r\nLocation: http://10.1.3.80:36866/apps/YouTube/run\r\n\
              Transfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            f.header,
            b"HTTP/1.1 201 Created\r\nLocation: http://10.1.1.5:44747/apps/YouTube/run\r\n\
              Transfer-Encoding: chunked\r\n\r\n"
        );
        assert_eq!(f.phase, Phase::BodyChunked); // 201 is NOT special-cased — chunked frames it
    }

    #[test]
    fn content_length_sets_the_body_phase() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nContent-Length: 1069\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::BodyContentLength);
        assert_eq!(f.body_remaining, 1069);
    }

    #[test]
    fn a_bodyless_status_has_no_body_despite_a_content_length() {
        // 204 is bodyless regardless of headers (RFC 7230 §3.3.3 rule 1).
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        f.scan_and_rewrite_header(b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::Header);
    }

    #[test]
    fn a_response_without_framing_is_close_delimited() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::BodyCloseDelimited);
    }

    #[test]
    fn a_request_without_framing_is_bodyless() {
        let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
        f.scan_and_rewrite_header(b"GET / HTTP/1.1\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::Header);
    }

    #[test]
    fn malformed_content_length_is_an_error() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        assert_eq!(
            f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nContent-Length: 12abc\r\n\r\n"),
            Err(FramingError::MalformedContentLength)
        );
    }

    #[test]
    fn chunked_in_a_coding_list_is_detected() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        f.scan_and_rewrite_header(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n")
            .unwrap();
        assert_eq!(f.phase, Phase::BodyChunked);
    }

    /// Drive `f` over `input` like the proxy: feed, record `(header, body)`, consume, until an
    /// incomplete header. Returns the framed messages as owned byte pairs.
    fn drain(f: &mut HttpFraming, input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut buf = input.to_vec();
        let mut out = Vec::new();
        loop {
            let framed = f.feed(&buf).unwrap();
            if framed.consumed == 0 {
                break;
            }
            let pair = (framed.header.to_vec(), framed.body.to_vec());
            let consumed = framed.consumed;
            out.push(pair);
            buf.drain(..consumed);
        }
        out
    }

    #[test]
    fn frames_a_content_length_message() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        let msgs = drain(&mut f, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].0, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
        assert_eq!(msgs[0].1, b"hello");
    }

    #[test]
    fn frames_a_chunked_message_forwarding_the_body_opaquely() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        let msgs = drain(
            &mut f,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n3\r\nbar\r\n0\r\n\r\n",
        );
        assert_eq!(msgs.len(), 1);
        assert_eq!(
            msgs[0].0,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        // The chunk framing rides out in the body untouched.
        assert_eq!(msgs[0].1, b"5\r\nhello\r\n3\r\nbar\r\n0\r\n\r\n");
    }

    #[test]
    fn frames_multiple_keep_alive_messages() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        // A Content-Length response immediately followed by a chunked one on the same connection.
        let msgs = drain(
            &mut f,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi\
              HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nbye\r\n0\r\n\r\n",
        );
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].1, b"hi");
        assert_eq!(msgs[1].1, b"3\r\nbye\r\n0\r\n\r\n");
    }

    #[test]
    fn forwards_chunked_trailers_opaquely() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        let msgs = drain(
            &mut f,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: v\r\n\r\n",
        );
        assert_eq!(msgs.len(), 1);
        // The trailer field and the closing blank line ride out in the body.
        assert_eq!(msgs[0].1, b"0\r\nX-Trailer: v\r\n\r\n");
    }

    #[test]
    fn chunk_size_line_over_cap_is_refused() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        let mut input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        input.resize(input.len() + MAX_CHUNK_LINE + 1, b'f'); // a chunk-size line that never terminates
        assert!(matches!(
            f.feed(&input),
            Err(FramingError::ChunkLineTooLong)
        ));
    }

    #[test]
    fn trailer_line_over_cap_is_refused() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        let mut input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        input.resize(input.len() + MAX_TRAILER_LINE + 1, b'a'); // a trailer line that never terminates
        assert!(matches!(
            f.feed(&input),
            Err(FramingError::TrailerLineTooLong)
        ));
    }

    #[test]
    fn a_trailer_line_past_the_chunk_cap_is_tolerated() {
        // A trailer line longer than MAX_CHUNK_LINE but within MAX_TRAILER_LINE isn't refused — it's
        // just incomplete, awaiting its CRLF. A chunk-size line of the same length would be rejected.
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        let mut input = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        input.resize(input.len() + MAX_CHUNK_LINE + 1, b'a');
        assert!(f.feed(&input).is_ok());
    }

    #[test]
    fn close_delimited_streams_the_body_across_feeds() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        let input = b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nabc";
        let first = f.feed(input).unwrap();
        assert_eq!(first.header, b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\n");
        assert_eq!(first.body, b"abc");
        assert_eq!(first.consumed, input.len()); // header + all arrived body
        // The phase stays close-delimited, so a later feed forwards more with no header.
        let second = f.feed(b"def").unwrap();
        assert_eq!(second.header, b"");
        assert_eq!(second.body, b"def");
    }

    #[test]
    fn streams_a_content_length_body_across_feeds() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        // First feed: header + 3 of the 5 declared body bytes.
        let first = f
            .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc")
            .unwrap();
        assert_eq!(
            first.header,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
        );
        assert_eq!(first.body, b"abc");
        // Second feed (after the owner consumed the first): the remaining 2 bytes, no header.
        let second = f.feed(b"de").unwrap();
        assert_eq!(second.header, b"");
        assert_eq!(second.body, b"de");
        assert_eq!(second.consumed, 2);
    }

    #[test]
    fn an_incomplete_header_consumes_nothing() {
        let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
        let framed = f.feed(b"GET / HTTP/1.1\r\nHost: x").unwrap(); // no blank line yet
        assert_eq!(framed.consumed, 0);
        assert_eq!(framed.header, b"");
        assert_eq!(framed.body, b"");
    }

    #[test]
    fn an_unterminated_oversize_header_errors() {
        let mut f = HttpFraming::new(Kind::Request, RewritePolicy::NONE);
        let huge = vec![b'x'; MAX_HEADER + 1]; // no blank line, over the cap
        assert!(matches!(f.feed(&huge), Err(FramingError::HeaderTooLong)));
    }

    #[test]
    fn a_malformed_chunk_size_errors() {
        let mut f = HttpFraming::new(Kind::Response, RewritePolicy::NONE);
        assert!(matches!(
            f.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\n"),
            Err(FramingError::MalformedChunkSize)
        ));
    }
}
