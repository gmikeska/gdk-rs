//! Network and HTTP utility functions for GDK.
//!
//! This module provides network communication utilities including:
//! - HTTP client with proxy and Tor support
//! - Request retry logic with exponential backoff
//! - Response validation and error handling
//! - Request/response logging for debugging
//! - Network connectivity testing and monitoring

use crate::{GdkError, Result};
use reqwest::{Client, ClientBuilder, Proxy, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use url::Url;

/// Default timeout for HTTP requests
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default maximum number of retry attempts
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default initial retry delay
pub const DEFAULT_INITIAL_RETRY_DELAY: Duration = Duration::from_millis(1000);

/// Maximum retry delay
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

/// HTTP client configuration
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// Request timeout
    pub timeout: Duration,
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial retry delay
    pub initial_retry_delay: Duration,
    /// HTTP proxy URL
    pub proxy_url: Option<String>,
    /// SOCKS5 proxy URL (for Tor)
    pub socks_proxy_url: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Enable request/response logging
    pub enable_logging: bool,
    /// Custom headers to include in all requests
    pub default_headers: Vec<(String, String)>,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            max_retries: DEFAULT_MAX_RETRIES,
            initial_retry_delay: DEFAULT_INITIAL_RETRY_DELAY,
            proxy_url: None,
            socks_proxy_url: None,
            user_agent: Some("gdk-rs/0.1.0".to_string()),
            enable_logging: false,
            default_headers: Vec::new(),
        }
    }
}

/// HTTP client with retry logic and proxy support
pub struct HttpClient {
    client: Client,
    config: HttpClientConfig,
}

impl HttpClient {
    /// Create a new HTTP client with the given configuration
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        let mut builder = ClientBuilder::new()
            .timeout(config.timeout)
            .danger_accept_invalid_certs(false);

        // Set user agent
        if let Some(user_agent) = &config.user_agent {
            builder = builder.user_agent(user_agent);
        }

        // Configure HTTP proxy
        if let Some(proxy_url) = &config.proxy_url {
            let proxy = Proxy::http(proxy_url)
                .map_err(|e| GdkError::Network(format!("Invalid HTTP proxy: {}", e)))?;
            builder = builder.proxy(proxy);
        }

        // Configure SOCKS proxy (for Tor)
        if let Some(socks_url) = &config.socks_proxy_url {
            let proxy = Proxy::all(socks_url)
                .map_err(|e| GdkError::Network(format!("Invalid SOCKS proxy: {}", e)))?;
            builder = builder.proxy(proxy);
        }

        let client = builder
            .build()
            .map_err(|e| GdkError::Network(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { client, config })
    }

    /// Create a default HTTP client
    pub fn default() -> Result<Self> {
        Self::new(HttpClientConfig::default())
    }

    /// Perform a GET request with retry logic
    pub async fn get(&self, url: &str) -> Result<Response> {
        self.request_with_retry("GET", url, None::<&()>).await
    }

    /// Perform a POST request with JSON body and retry logic
    pub async fn post_json<T: Serialize>(&self, url: &str, body: &T) -> Result<Response> {
        self.request_with_retry("POST", url, Some(body)).await
    }

    /// Perform a PUT request with JSON body and retry logic
    pub async fn put_json<T: Serialize>(&self, url: &str, body: &T) -> Result<Response> {
        self.request_with_retry("PUT", url, Some(body)).await
    }

    /// Perform a DELETE request with retry logic
    pub async fn delete(&self, url: &str) -> Result<Response> {
        self.request_with_retry("DELETE", url, None::<&()>).await
    }

    /// Perform a request with retry logic and exponential backoff
    async fn request_with_retry<T: Serialize>(
        &self,
        method: &str,
        url: &str,
        body: Option<&T>,
    ) -> Result<Response> {
        let mut last_error = None;
        let mut retry_delay = self.config.initial_retry_delay;

        for attempt in 0..=self.config.max_retries {
            if self.config.enable_logging {
                log::debug!("HTTP {} request to {} (attempt {})", method, url, attempt + 1);
            }

            let start_time = Instant::now();
            let result = self.make_request(method, url, body).await;
            let duration = start_time.elapsed();

            match result {
                Ok(response) => {
                    if self.config.enable_logging {
                        log::debug!(
                            "HTTP {} {} completed in {:?} with status {}",
                            method,
                            url,
                            duration,
                            response.status()
                        );
                    }

                    // Check if we should retry based on status code
                    if self.should_retry_status(response.status()) && attempt < self.config.max_retries {
                        if self.config.enable_logging {
                            log::warn!(
                                "HTTP {} {} returned {}, retrying in {:?}",
                                method,
                                url,
                                response.status(),
                                retry_delay
                            );
                        }
                        sleep(retry_delay).await;
                        retry_delay = std::cmp::min(retry_delay * 2, MAX_RETRY_DELAY);
                        continue;
                    }

                    return Ok(response);
                }
                Err(e) => {
                    if self.config.enable_logging {
                        log::warn!(
                            "HTTP {} {} failed in {:?}: {}",
                            method,
                            url,
                            duration,
                            e
                        );
                    }

                    last_error = Some(e);

                    // Don't retry on the last attempt
                    if attempt < self.config.max_retries {
                        if self.config.enable_logging {
                            log::info!("Retrying in {:?}", retry_delay);
                        }
                        sleep(retry_delay).await;
                        retry_delay = std::cmp::min(retry_delay * 2, MAX_RETRY_DELAY);
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            GdkError::Network("All retry attempts failed".to_string())
        }))
    }

    /// Make a single HTTP request
    async fn make_request<T: Serialize>(
        &self,
        method: &str,
        url: &str,
        body: Option<&T>,
    ) -> Result<Response> {
        let mut request_builder = match method {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            "PUT" => self.client.put(url),
            "DELETE" => self.client.delete(url),
            _ => return Err(GdkError::Network(format!("Unsupported HTTP method: {}", method))),
        };

        // Add default headers
        for (key, value) in &self.config.default_headers {
            request_builder = request_builder.header(key, value);
        }

        // Add JSON body if provided
        if let Some(body) = body {
            request_builder = request_builder.json(body);
        }

        let response = request_builder
            .send()
            .await
            .map_err(|e| GdkError::Network(format!("HTTP request failed: {}", e)))?;

        Ok(response)
    }

    /// Check if a status code should trigger a retry
    fn should_retry_status(&self, status: StatusCode) -> bool {
        matches!(
            status,
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
                | StatusCode::INTERNAL_SERVER_ERROR
                | StatusCode::BAD_GATEWAY
                | StatusCode::SERVICE_UNAVAILABLE
                | StatusCode::GATEWAY_TIMEOUT
        )
    }
}

/// Response validation utilities
pub struct ResponseValidator;

impl ResponseValidator {
    /// Validate that a response has a successful status code
    pub fn validate_success(response: &Response) -> Result<()> {
        if response.status().is_success() {
            Ok(())
        } else {
            Err(GdkError::Network(format!(
                "HTTP request failed with status: {}",
                response.status()
            )))
        }
    }

    /// Validate and parse JSON response
    pub async fn validate_json<T: for<'de> Deserialize<'de>>(response: Response) -> Result<T> {
        Self::validate_success(&response)?;
        
        response
            .json::<T>()
            .await
            .map_err(|e| GdkError::Network(format!("Failed to parse JSON response: {}", e)))
    }

    /// Validate and get response text
    pub async fn validate_text(response: Response) -> Result<String> {
        Self::validate_success(&response)?;
        
        response
            .text()
            .await
            .map_err(|e| GdkError::Network(format!("Failed to get response text: {}", e)))
    }

    /// Validate and get response bytes
    pub async fn validate_bytes(response: Response) -> Result<Vec<u8>> {
        Self::validate_success(&response)?;
        
        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| GdkError::Network(format!("Failed to get response bytes: {}", e)))
    }

    /// Check if response indicates rate limiting
    pub fn is_rate_limited(response: &Response) -> bool {
        response.status() == StatusCode::TOO_MANY_REQUESTS
    }

    /// Extract rate limit information from headers
    pub fn get_rate_limit_info(response: &Response) -> Option<RateLimitInfo> {
        let headers = response.headers();
        
        let limit = headers
            .get("x-ratelimit-limit")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
            
        let remaining = headers
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
            
        let reset = headers
            .get("x-ratelimit-reset")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        if limit.is_some() || remaining.is_some() || reset.is_some() {
            Some(RateLimitInfo {
                limit,
                remaining,
                reset,
            })
        } else {
            None
        }
    }
}

/// Rate limit information extracted from response headers
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub limit: Option<u64>,
    pub remaining: Option<u64>,
    pub reset: Option<u64>,
}

/// Network connectivity testing utilities
pub struct ConnectivityTester {
    client: HttpClient,
}

impl ConnectivityTester {
    /// Create a new connectivity tester
    pub fn new() -> Result<Self> {
        let config = HttpClientConfig {
            timeout: Duration::from_secs(10),
            max_retries: 1,
            enable_logging: true,
            ..Default::default()
        };
        
        Ok(Self {
            client: HttpClient::new(config)?,
        })
    }

    /// Test basic internet connectivity
    pub async fn test_internet_connectivity(&self) -> bool {
        let test_urls = [
            "https://www.google.com",
            "https://www.cloudflare.com",
            "https://httpbin.org/get",
        ];

        for url in &test_urls {
            if let Ok(response) = self.client.get(url).await {
                if response.status().is_success() {
                    log::info!("Internet connectivity confirmed via {}", url);
                    return true;
                }
            }
        }

        log::warn!("Internet connectivity test failed");
        false
    }

    /// Test connectivity to a specific host
    pub async fn test_host_connectivity(&self, url: &str) -> Result<Duration> {
        let start_time = Instant::now();
        let response = self.client.get(url).await?;
        let duration = start_time.elapsed();

        ResponseValidator::validate_success(&response)?;
        
        log::info!("Host {} is reachable in {:?}", url, duration);
        Ok(duration)
    }

    /// Test proxy connectivity
    pub async fn test_proxy_connectivity(&self, proxy_url: &str) -> Result<()> {
        let config = HttpClientConfig {
            proxy_url: Some(proxy_url.to_string()),
            timeout: Duration::from_secs(15),
            max_retries: 1,
            ..Default::default()
        };

        let client = HttpClient::new(config)?;
        let response = client.get("https://httpbin.org/ip").await?;
        ResponseValidator::validate_success(&response)?;

        log::info!("Proxy {} is working", proxy_url);
        Ok(())
    }

    /// Test Tor connectivity
    pub async fn test_tor_connectivity(&self, socks_proxy_url: &str) -> Result<()> {
        let config = HttpClientConfig {
            socks_proxy_url: Some(socks_proxy_url.to_string()),
            timeout: Duration::from_secs(30),
            max_retries: 1,
            ..Default::default()
        };

        let client = HttpClient::new(config)?;
        
        // Test with a .onion address if possible, otherwise use regular HTTPS
        let test_url = "https://check.torproject.org/api/ip";
        let response = client.get(test_url).await?;
        ResponseValidator::validate_success(&response)?;

        log::info!("Tor connectivity confirmed via {}", socks_proxy_url);
        Ok(())
    }
}

impl Default for ConnectivityTester {
    fn default() -> Self {
        Self::new().expect("Failed to create default connectivity tester")
    }
}

/// URL validation and parsing utilities
pub struct UrlUtils;

impl UrlUtils {
    /// Validate and parse a URL
    pub fn parse_url(url_str: &str) -> Result<Url> {
        Url::parse(url_str)
            .map_err(|e| GdkError::Network(format!("Invalid URL '{}': {}", url_str, e)))
    }

    /// Check if a URL uses HTTPS
    pub fn is_https(url: &Url) -> bool {
        url.scheme() == "https"
    }

    /// Check if a URL is a .onion address
    pub fn is_onion_address(url: &Url) -> bool {
        url.host_str()
            .map(|host| host.ends_with(".onion"))
            .unwrap_or(false)
    }

    /// Extract host and port from URL
    pub fn get_host_port(url: &Url) -> Result<(String, u16)> {
        let host = url.host_str()
            .ok_or_else(|| GdkError::Network("URL has no host".to_string()))?
            .to_string();
            
        let port = url.port_or_known_default()
            .ok_or_else(|| GdkError::Network("Cannot determine port".to_string()))?;
            
        Ok((host, port))
    }

    /// Build a URL with query parameters
    pub fn build_url_with_params(base_url: &str, params: &[(&str, &str)]) -> Result<String> {
        let mut url = Self::parse_url(base_url)?;
        
        {
            let mut query_pairs = url.query_pairs_mut();
            for (key, value) in params {
                query_pairs.append_pair(key, value);
            }
        }
        
        Ok(url.to_string())
    }
}

/// Network monitoring utilities
pub struct NetworkMonitor {
    client: HttpClient,
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new() -> Result<Self> {
        let config = HttpClientConfig {
            timeout: Duration::from_secs(5),
            max_retries: 0,
            enable_logging: false,
            ..Default::default()
        };
        
        Ok(Self {
            client: HttpClient::new(config)?,
        })
    }

    /// Monitor network latency to a specific endpoint
    pub async fn measure_latency(&self, url: &str) -> Result<Duration> {
        let start_time = Instant::now();
        let response = self.client.get(url).await?;
        let latency = start_time.elapsed();

        ResponseValidator::validate_success(&response)?;
        Ok(latency)
    }

    /// Perform a series of latency measurements
    pub async fn measure_average_latency(&self, url: &str, samples: usize) -> Result<Duration> {
        let mut total_latency = Duration::ZERO;
        let mut successful_samples = 0;

        for _ in 0..samples {
            if let Ok(latency) = self.measure_latency(url).await {
                total_latency += latency;
                successful_samples += 1;
            }
            
            // Small delay between samples
            sleep(Duration::from_millis(100)).await;
        }

        if successful_samples == 0 {
            return Err(GdkError::Network("No successful latency measurements".to_string()));
        }

        Ok(total_latency / successful_samples as u32)
    }

    /// Check if a service is available
    pub async fn is_service_available(&self, url: &str) -> bool {
        self.client.get(url).await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
    }
}

impl Default for NetworkMonitor {
    fn default() -> Self {
        Self::new().expect("Failed to create default network monitor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_http_client_creation() {
        let config = HttpClientConfig::default();
        let client = HttpClient::new(config);
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_url_validation() {
        assert!(UrlUtils::parse_url("https://example.com").is_ok());
        assert!(UrlUtils::parse_url("invalid-url").is_err());
        
        let url = UrlUtils::parse_url("https://example.com").unwrap();
        assert!(UrlUtils::is_https(&url));
        assert!(!UrlUtils::is_onion_address(&url));
    }

    #[tokio::test]
    async fn test_url_with_params() {
        let params = [("key1", "value1"), ("key2", "value2")];
        let url = UrlUtils::build_url_with_params("https://example.com", &params).unwrap();
        assert!(url.contains("key1=value1"));
        assert!(url.contains("key2=value2"));
    }

    #[test]
    fn test_onion_address_detection() {
        let onion_url = UrlUtils::parse_url("https://example.onion").unwrap();
        assert!(UrlUtils::is_onion_address(&onion_url));
        
        let regular_url = UrlUtils::parse_url("https://example.com").unwrap();
        assert!(!UrlUtils::is_onion_address(&regular_url));
    }

    #[test]
    fn test_host_port_extraction() {
        let url = UrlUtils::parse_url("https://example.com:8080").unwrap();
        let (host, port) = UrlUtils::get_host_port(&url).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_rate_limit_info() {
        // This would require a mock response with headers
        // For now, just test the structure
        let info = RateLimitInfo {
            limit: Some(100),
            remaining: Some(50),
            reset: Some(1234567890),
        };
        assert_eq!(info.limit, Some(100));
        assert_eq!(info.remaining, Some(50));
        assert_eq!(info.reset, Some(1234567890));
    }
}