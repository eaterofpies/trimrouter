use crate::logging::{LevelFilter, get_recent_logs, get_ring_buffer_len, subscribe_logs};
use crate::services::observability::html::DASHBOARD_HTML;
use crate::services::observability::status::{
    LogsResponse, ObservabilityReceivers, StatusResponse, collect_status_response,
};
use axum::Router;
use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderValue};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::get;
use futures_util::stream::BoxStream;
use futures_util::{Stream, StreamExt};
use log::{debug, warn};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::net::TcpListener;
use tokio::sync::watch::Receiver as WatchReceiver;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_stream::wrappers::BroadcastStream;
use tower::limit::ConcurrencyLimitLayer;

pub const HTTP_PORT: u16 = 80;
pub const MAX_CONCURRENT_HTTP_CONNECTIONS: usize = 16;
pub const MAX_CONCURRENT_SSE_STREAMS: usize = 4;
pub const MAX_SSE_STREAMS_PER_IP: usize = 2;
pub const DEFAULT_LOG_LINES_COUNT: usize = 100;
pub const MAX_LOG_LINES_COUNT: usize = 500;

#[derive(Clone)]
pub struct AppState {
    pub lan_interface: String,
    pub lan_ip: String,
    pub receivers: ObservabilityReceivers,
    pub sse_semaphore: Arc<Semaphore>,
    pub sse_ip_tracker: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFilterParam {
    Off,
    Error,
    #[serde(alias = "warning")]
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<LogFilterParam> for LevelFilter {
    fn from(param: LogFilterParam) -> Self {
        match param {
            LogFilterParam::Off => LevelFilter::Off,
            LogFilterParam::Error => LevelFilter::Error,
            LogFilterParam::Warn => LevelFilter::Warn,
            LogFilterParam::Info => LevelFilter::Info,
            LogFilterParam::Debug => LevelFilter::Debug,
            LogFilterParam::Trace => LevelFilter::Trace,
        }
    }
}

impl std::str::FromStr for LogFilterParam {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(()),
        }
    }
}

#[derive(Deserialize, Default)]
pub struct LogsQueryParams {
    pub lines: Option<usize>,
    pub level: Option<LogFilterParam>,
}

pub struct IpStreamPermit {
    client_ip: IpAddr,
    ip_tracker: Arc<Mutex<HashMap<IpAddr, usize>>>,
    _global_permit: OwnedSemaphorePermit,
}

impl Drop for IpStreamPermit {
    fn drop(&mut self) {
        if let Ok(mut map) = self.ip_tracker.lock()
            && let Some(count) = map.get_mut(&self.client_ip)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.client_ip);
            }
        }
    }
}

pub struct StreamPermitGuard<S> {
    inner: S,
    _permit: IpStreamPermit,
}

impl<S> StreamPermitGuard<S> {
    pub fn new(inner: S, permit: IpStreamPermit) -> Self {
        Self {
            inner,
            _permit: permit,
        }
    }
}

impl<S: Stream + Unpin> Stream for StreamPermitGuard<S> {
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

pub fn extract_host_name(host_header: &str) -> &str {
    let trimmed = host_header.trim();
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return &trimmed[..=end + 1];
    }
    if trimmed.matches(':').count() > 1 {
        return trimmed;
    }
    trimmed.split(':').next().unwrap_or("")
}

pub fn is_allowed_host(host_header: &str, lan_ip: &str) -> bool {
    let host = extract_host_name(host_header);
    if host.is_empty() {
        return false;
    }

    if host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
        || host.eq_ignore_ascii_case("router.lan")
        || host.eq_ignore_ascii_case("router")
        || host.eq_ignore_ascii_case("router.local")
    {
        return true;
    }

    let ip_only = lan_ip.split('/').next().unwrap_or("");
    !ip_only.is_empty() && host.eq_ignore_ascii_case(ip_only)
}

pub async fn validate_host_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();

    if !is_allowed_host(host_header, &state.lan_ip) {
        warn!("[observability] Rejected request with invalid Host header: '{host_header}'");
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(next.run(req).await)
}

pub async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self';",
        ),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

pub struct HttpServer {
    listener: TcpListener,
    state: AppState,
}

impl HttpServer {
    pub fn new(
        listener: TcpListener,
        lan_interface: String,
        lan_ip: String,
        receivers: ObservabilityReceivers,
    ) -> Self {
        let state = AppState {
            lan_interface,
            lan_ip,
            receivers,
            sse_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_SSE_STREAMS)),
            sse_ip_tracker: Arc::new(Mutex::new(HashMap::new())),
        };
        Self { listener, state }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self, mut shutdown_rx: WatchReceiver<bool>) {
        let app = create_router(self.state);
        let serve = axum::serve(
            self.listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        );
        let graceful = serve.with_graceful_shutdown(async move {
            let _ = shutdown_rx.changed().await;
        });

        if let Err(e) = graceful.await {
            warn!("[observability] HTTP server encountered an error: {e}");
        }
    }
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(handle_dashboard))
        .route("/api/status", get(handle_status))
        .route("/api/logs", get(handle_logs))
        .route("/api/logs/stream", get(handle_logs_stream))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_HTTP_CONNECTIONS))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            validate_host_middleware,
        ))
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(state)
}

async fn handle_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn handle_status(State(state): State<AppState>) -> Json<StatusResponse> {
    let status = collect_status_response(&state.receivers, &state.lan_interface, &state.lan_ip);
    Json(status)
}

async fn handle_logs(Query(params): Query<LogsQueryParams>) -> Json<LogsResponse> {
    let lines_count = params
        .lines
        .unwrap_or(DEFAULT_LOG_LINES_COUNT)
        .min(MAX_LOG_LINES_COUNT);
    let level_filter = params.level.map(LevelFilter::from);
    let lines = get_recent_logs(lines_count, level_filter);
    let total_lines_available = get_ring_buffer_len();

    Json(LogsResponse {
        total_lines_available,
        lines,
    })
}

fn reserve_ip_sse_slot(
    ip_tracker: &Arc<Mutex<HashMap<IpAddr, usize>>>,
    client_ip: IpAddr,
) -> Result<(), StatusCode> {
    let mut map = ip_tracker
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let count = map.entry(client_ip).or_insert(0);
    if *count >= MAX_SSE_STREAMS_PER_IP {
        warn!(
            "[observability] Client {} reached per-IP SSE stream limit ({})",
            client_ip, MAX_SSE_STREAMS_PER_IP
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    *count += 1;
    Ok(())
}

fn release_ip_sse_slot(ip_tracker: &Arc<Mutex<HashMap<IpAddr, usize>>>, client_ip: &IpAddr) {
    if let Ok(mut map) = ip_tracker.lock()
        && let Some(count) = map.get_mut(client_ip)
    {
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(client_ip);
        }
    }
}

async fn handle_logs_stream(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> Response {
    let client_ip = addr.ip();

    if let Err(status) = reserve_ip_sse_slot(&state.sse_ip_tracker, client_ip) {
        return status.into_response();
    }

    let permit = match state.sse_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            warn!(
                "[observability] Max concurrent SSE streams ({}) reached. Rejecting stream request.",
                MAX_CONCURRENT_SSE_STREAMS
            );
            release_ip_sse_slot(&state.sse_ip_tracker, &client_ip);
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
    };

    let ip_permit = IpStreamPermit {
        client_ip,
        ip_tracker: state.sse_ip_tracker.clone(),
        _global_permit: permit,
    };

    debug!("[observability] Client {client_ip} connected to SSE log stream");
    let log_rx = subscribe_logs();
    let stream: BoxStream<'static, Result<Event, Infallible>> =
        Box::pin(BroadcastStream::new(log_rx).filter_map(|res| async move {
            match res {
                Ok(line) => {
                    let clean = line.trim_end().to_string();
                    Some(Ok(Event::default().data(clean)))
                }
                Err(_) => None,
            }
        }));

    let guarded_stream = StreamPermitGuard::new(stream, ip_permit);
    Sse::new(guarded_stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::push_to_ring_buffer_and_broadcast;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;
    use tokio::sync::watch;

    #[test]
    fn test_log_filter_param_from_str_and_conversion() {
        assert_eq!("error".parse::<LogFilterParam>(), Ok(LogFilterParam::Error));
        assert_eq!("WARN".parse::<LogFilterParam>(), Ok(LogFilterParam::Warn));
        assert_eq!(
            "warning".parse::<LogFilterParam>(),
            Ok(LogFilterParam::Warn)
        );
        assert_eq!("info".parse::<LogFilterParam>(), Ok(LogFilterParam::Info));
        assert_eq!("debug".parse::<LogFilterParam>(), Ok(LogFilterParam::Debug));
        assert_eq!("trace".parse::<LogFilterParam>(), Ok(LogFilterParam::Trace));
        assert_eq!("off".parse::<LogFilterParam>(), Ok(LogFilterParam::Off));
        assert!("invalid".parse::<LogFilterParam>().is_err());

        assert_eq!(LevelFilter::from(LogFilterParam::Error), LevelFilter::Error);
        assert_eq!(LevelFilter::from(LogFilterParam::Warn), LevelFilter::Warn);
        assert_eq!(LevelFilter::from(LogFilterParam::Info), LevelFilter::Info);
        assert_eq!(LevelFilter::from(LogFilterParam::Debug), LevelFilter::Debug);
        assert_eq!(LevelFilter::from(LogFilterParam::Trace), LevelFilter::Trace);
        assert_eq!(LevelFilter::from(LogFilterParam::Off), LevelFilter::Off);
    }

    #[tokio::test]
    async fn test_http_server_endpoints() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (_lease_tx, lease_rx) = watch::channel(crate::services::WanLease::default());
        let (_dhcp_tx, dhcp_rx) = watch::channel(Vec::new());
        let (_dns_tx, dns_rx) = watch::channel(crate::services::ipc::DnsStatsInfo::default());
        let (_sntp_tx, sntp_rx) =
            watch::channel(crate::services::observability::status::SntpStatus::default());
        let (_watchdog_tx, watchdog_rx) = watch::channel(false);
        let receivers =
            ObservabilityReceivers::new(lease_rx, dhcp_rx, dns_rx, sntp_rx, watchdog_rx);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = HttpServer::new(
            listener,
            "lan".to_string(),
            "192.168.1.1/24".to_string(),
            receivers,
        );
        tokio::spawn(async move {
            server.run(shutdown_rx).await;
        });

        // 1. Test GET / (HTML Dashboard)
        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader = BufReader::new(client);
        let mut first_line = String::new();
        reader.read_line(&mut first_line).await.unwrap();
        assert!(first_line.contains("200 OK"));

        // 2. Test GET /api/status (JSON)
        let mut client2 = TcpStream::connect(addr).await.unwrap();
        client2
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader2 = BufReader::new(client2);
        let mut status_line = String::new();
        reader2.read_line(&mut status_line).await.unwrap();
        assert!(status_line.contains("200 OK"));

        // 3. Test GET /api/logs (JSON)
        push_to_ring_buffer_and_broadcast("[2026-09-27T18:30:00Z] [INFO] [test] Test log entry\n");
        let mut client3 = TcpStream::connect(addr).await.unwrap();
        client3
            .write_all(b"GET /api/logs?lines=10&level=info HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader3 = BufReader::new(client3);
        let mut logs_line = String::new();
        reader3.read_line(&mut logs_line).await.unwrap();
        assert!(logs_line.contains("200 OK"));

        // 4. Test Method Not Allowed (POST /api/status)
        let mut client4 = TcpStream::connect(addr).await.unwrap();
        client4
            .write_all(b"POST /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader4 = BufReader::new(client4);
        let mut not_allowed_line = String::new();
        reader4.read_line(&mut not_allowed_line).await.unwrap();
        assert!(not_allowed_line.contains("405 Method Not Allowed"));

        // 5. Test Not Found (GET /nonexistent)
        let mut client5 = TcpStream::connect(addr).await.unwrap();
        client5
            .write_all(b"GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader5 = BufReader::new(client5);
        let mut not_found_line = String::new();
        reader5.read_line(&mut not_found_line).await.unwrap();
        assert!(not_found_line.contains("404 Not Found"));

        // 6. Test Security Headers Present
        let mut client6 = TcpStream::connect(addr).await.unwrap();
        client6
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut reader6 = BufReader::new(client6);
        let mut headers_buf = String::new();
        loop {
            let mut line = String::new();
            if reader6.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
                break;
            }
            headers_buf.push_str(&line);
        }
        assert!(headers_buf.contains("x-frame-options: DENY"));
        assert!(headers_buf.contains("x-content-type-options: nosniff"));
        assert!(headers_buf.contains("content-security-policy"));
        assert!(headers_buf.contains("referrer-policy: no-referrer"));

        // 7. Test Invalid Host Header Rejected (DNS Rebinding Mitigation)
        let mut client7 = TcpStream::connect(addr).await.unwrap();
        client7
            .write_all(b"GET / HTTP/1.1\r\nHost: evil.attacker.com\r\n\r\n")
            .await
            .unwrap();
        let mut reader7 = BufReader::new(client7);
        let mut rebind_line = String::new();
        reader7.read_line(&mut rebind_line).await.unwrap();
        assert!(rebind_line.contains("400 Bad Request"));

        // Clean shutdown
        let _ = shutdown_tx.send(true);
    }

    #[test]
    fn test_host_header_validation() {
        let lan_ip = "192.168.1.1/24";
        assert!(is_allowed_host("localhost", lan_ip));
        assert!(is_allowed_host("localhost:80", lan_ip));
        assert!(is_allowed_host("127.0.0.1", lan_ip));
        assert!(is_allowed_host("127.0.0.1:8080", lan_ip));
        assert!(is_allowed_host("::1", lan_ip));
        assert!(is_allowed_host("[::1]", lan_ip));
        assert!(is_allowed_host("[::1]:80", lan_ip));
        assert!(is_allowed_host("router.lan", lan_ip));
        assert!(is_allowed_host("ROUTER.LAN:80", lan_ip));
        assert!(is_allowed_host("router", lan_ip));
        assert!(is_allowed_host("router.local", lan_ip));
        assert!(is_allowed_host("192.168.1.1", lan_ip));
        assert!(is_allowed_host("192.168.1.1:80", lan_ip));

        assert!(!is_allowed_host("", lan_ip));
        assert!(!is_allowed_host("attacker.com", lan_ip));
        assert!(!is_allowed_host("evil.router.lan", lan_ip));
        assert!(!is_allowed_host("192.168.1.2", lan_ip));
    }

    #[tokio::test]
    async fn test_per_ip_sse_rate_limiting() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (_lease_tx, lease_rx) = watch::channel(crate::services::WanLease::default());
        let (_dhcp_tx, dhcp_rx) = watch::channel(Vec::new());
        let (_dns_tx, dns_rx) = watch::channel(crate::services::ipc::DnsStatsInfo::default());
        let (_sntp_tx, sntp_rx) =
            watch::channel(crate::services::observability::status::SntpStatus::default());
        let (_watchdog_tx, watchdog_rx) = watch::channel(false);
        let receivers =
            ObservabilityReceivers::new(lease_rx, dhcp_rx, dns_rx, sntp_rx, watchdog_rx);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let server = HttpServer::new(
            listener,
            "lan".to_string(),
            "192.168.1.1/24".to_string(),
            receivers,
        );
        tokio::spawn(async move {
            server.run(shutdown_rx).await;
        });

        // 1st SSE stream from 127.0.0.1
        let mut c1 = TcpStream::connect(addr).await.unwrap();
        c1.write_all(b"GET /api/logs/stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut r1 = BufReader::new(&mut c1);
        let mut l1 = String::new();
        r1.read_line(&mut l1).await.unwrap();
        assert!(l1.contains("200 OK"));

        // 2nd SSE stream from 127.0.0.1
        let mut c2 = TcpStream::connect(addr).await.unwrap();
        c2.write_all(b"GET /api/logs/stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut r2 = BufReader::new(&mut c2);
        let mut l2 = String::new();
        r2.read_line(&mut l2).await.unwrap();
        assert!(l2.contains("200 OK"));

        // 3rd SSE stream from 127.0.0.1 -> Exceeds MAX_SSE_STREAMS_PER_IP (2) -> 429
        let mut c3 = TcpStream::connect(addr).await.unwrap();
        c3.write_all(b"GET /api/logs/stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut r3 = BufReader::new(&mut c3);
        let mut l3 = String::new();
        r3.read_line(&mut l3).await.unwrap();
        assert!(l3.contains("429 Too Many Requests"));

        // Drop 1st client connection
        drop(c1);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 4th SSE stream -> Now succeeds because 1st was closed
        let mut c4 = TcpStream::connect(addr).await.unwrap();
        c4.write_all(b"GET /api/logs/stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut r4 = BufReader::new(&mut c4);
        let mut l4 = String::new();
        r4.read_line(&mut l4).await.unwrap();
        assert!(l4.contains("200 OK"));

        let _ = shutdown_tx.send(true);
    }
}
