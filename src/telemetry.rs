use crate::config::TracingConfig;
use anyhow::Context;
use axum::http::{HeaderMap, Request};
use opentelemetry::{propagation::Extractor, trace::TracerProvider};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{propagation::TraceContextPropagator, trace::SdkTracerProvider, Resource};
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init(config: Option<&TracingConfig>) -> anyhow::Result<Option<SdkTracerProvider>> {
    let provider = config
        .map(|config| {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&config.endpoint)
                .build()
                .context("failed to configure OTLP trace exporter")?;
            Ok::<_, anyhow::Error>(
                SdkTracerProvider::builder()
                    .with_batch_exporter(exporter)
                    .with_resource(Resource::builder().with_service_name("idmouse").build())
                    .build(),
            )
        })
        .transpose()?;
    let telemetry = provider
        .as_ref()
        .map(|provider| tracing_opentelemetry::layer().with_tracer(provider.tracer("idmouse")));
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            "warn,idmouse=debug,authzoo=debug,tower_http=info,axum::rejection=trace",
        ))
        .with(tracing_subscriber::fmt::layer().compact())
        .with(telemetry)
        .try_init()?;
    Ok(provider)
}

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key)?.to_str().ok()
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|key| key.as_str()).collect()
    }
}

pub fn request_span<B>(request: &Request<B>) -> Span {
    use opentelemetry::propagation::TextMapPropagator;
    let span = tracing::info_span!(
        "request",
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        http.response.status_code = tracing::field::Empty,
        method = %request.method(),
        uri = %request.uri().path(),
        version = ?request.version(),
    );
    let parent = TraceContextPropagator::new().extract(&HeaderExtractor(request.headers()));
    let _ = span.set_parent(parent);
    span
}

pub fn response<B>(response: &axum::http::Response<B>, latency: std::time::Duration, span: &Span) {
    span.record("http.response.status_code", response.status().as_u16());
    if response.status().is_server_error() {
        span.record("otel.status_code", "ERROR");
    }
    tracing::info!(parent: span, status = %response.status(), ?latency, "finished processing request");
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for Ctrl-C");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to listen for SIGTERM"),
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::{SpanKind, TraceId};
    use opentelemetry_sdk::trace::InMemorySpanExporter;

    #[test]
    fn request_spans_continue_remote_context_and_capture_diagnostics() {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        tracing::subscriber::with_default(subscriber, || {
            let request = Request::builder()
                .method("POST")
                .uri("/token/example?secret=omitted")
                .header("authorization", "Bearer secret-token")
                .header(
                    "traceparent",
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                )
                .header("tracestate", "vendor=opaque")
                .body(())
                .unwrap();
            let span = request_span(&request);
            let _entered = span.enter();
            tracing::debug!(target: "authzoo", reason = "InvalidAudience", "token did not match role");
        });
        provider.force_flush().unwrap();
        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        let span = &spans[0];
        assert_eq!(span.span_kind, SpanKind::Server);
        assert_eq!(
            span.span_context.trace_id(),
            TraceId::from_hex("4bf92f3577b34da6a3ce929d0e0e4736").unwrap()
        );
        assert_eq!(span.parent_span_id.to_string(), "00f067aa0ba902b7");
        assert_eq!(span.span_context.trace_state().header(), "vendor=opaque");
        assert_eq!(span.events.len(), 1);
        assert!(span.events[0]
            .attributes
            .iter()
            .any(|attribute| attribute.key.as_str() == "reason"
                && attribute.value.as_str() == "InvalidAudience"));
        let attributes = format!("{:?}", span.attributes);
        assert!(attributes.contains("/token/example"));
        assert!(!attributes.contains("secret"));
        provider.shutdown().unwrap();
    }
}
