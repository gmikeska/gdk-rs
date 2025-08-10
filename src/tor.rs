//! Tor integration for privacy-preserving network connections.
//! 
//! This module provides SOCKS5 proxy support, onion service connections,
//! circuit management, and Tor-specific error handling.

use crate::error::GdkError;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::time::{interval, timeout};

/// SOCKS5 protocol constants
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_USERNAME_PASSWORD: u8 = 0x02;
const SOCKS5_CONNECT: u8 = 0x01;
const SOCKS5_IPV4: u8 = 0x01;
const SOCKS5_DOMAIN: u8 = 0x03;
const SOCKS5_IPV6: u8 = 0x04;

/// Tor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorConfig {
    /// SOCKS5 proxy address (usually 127.0.0.1:9050)
    pub socks_proxy: SocketAddr,
    /// Control port address (usually 127.0.0.1:9051)
    pub control_port: Option<SocketAddr>,
    /// Authentication password for control port
    pub control_password: Option<String>,
    /// Enable circuit rotation
    pub enable_circuit_rotation: bool,
    /// Circuit rotation interval
    pub circuit_rotation_interval: Duration,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Maximum number of retries
    pub max_retries: u32,
    /// Retry delay
    pub retry_delay: Duration,
    /// Enable onion service connections
    pub enable_onion_services: bool,
    /// Preferred onion service endpoints
    pub onion_endpoints: Vec<String>,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            socks_proxy: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9050),
            control_port: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9051)),
            control_password: None,
            enable_circuit_rotation: true,
            circuit_rotation_interval: Duration::from_secs(600), // 10 minutes
            connection_timeout: Duration::from_secs(30),
            max_retries: 3,
            retry_delay: Duration::from_secs(2),
            enable_onion_services: true,
            onion_endpoints: Vec::new(),
        }
    }
}

/// Tor connection statistics
#[derive(Debug, Clone, Default)]
pub struct TorStats {
    pub connections_established: u64,
    pub connections_failed: u64,
    pub circuits_created: u64,
    pub circuits_failed: u64,
    pub onion_connections: u64,
    pub clearnet_connections: u64,
    pub last_circuit_rotation: Option<Instant>,
}

/// Tor circuit information
#[derive(Debug, Clone)]
pub struct TorCircuit {
    pub id: String,
    pub created_at: Instant,
    pub path: Vec<String>, // Relay fingerprints
    pub status: CircuitStatus,
}

/// Circuit status
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitStatus {
    Building,
    Built,
    Failed,
    Closed,
}

/// Tor connection manager
pub struct TorManager {
    config: TorConfig,
    stats: Arc<RwLock<TorStats>>,
    circuits: Arc<Mutex<HashMap<String, TorCircuit>>>,
    control_connection: Arc<Mutex<Option<TorControlConnection>>>,
}

impl TorManager {
    pub fn new(config: TorConfig) -> Self {
        let manager = Self {
            config: config.clone(),
            stats: Arc::new(RwLock::new(TorStats::default())),
            circuits: Arc::new(Mutex::new(HashMap::new())),
            control_connection: Arc::new(Mutex::new(None)),
        };

        // Start circuit rotation if enabled
        if config.enable_circuit_rotation {
            let circuits = manager.circuits.clone();
            let control_conn = manager.control_connection.clone();
            let rotation_interval = config.circuit_rotation_interval;
            
            tokio::spawn(async move {
                let mut interval = interval(rotation_interval);
                loop {
                    interval.tick().await;
                    if let Err(e) = Self::rotate_circuits(&circuits, &control_conn).await {
                        log::warn!("Failed to rotate Tor circuits: {}", e);
                    }
                }
            });
        }

        manager
    }

    /// Connect through Tor SOCKS5 proxy
    pub async fn connect(&self, target: &str, port: u16) -> Result<TcpStream> {
        let mut retries = 0;
        
        while retries < self.config.max_retries {
            match self.try_connect(target, port).await {
                Ok(stream) => {
                    self.update_stats_success(target).await;
                    return Ok(stream);
                }
                Err(e) => {
                    retries += 1;
                    if retries >= self.config.max_retries {
                        self.update_stats_failure().await;
                        return Err(e);
                    }
                    
                    log::warn!("Tor connection attempt {} failed: {}, retrying...", retries, e);
                    tokio::time::sleep(self.config.retry_delay).await;
                }
            }
        }
        
        Err(GdkError::Network("Max Tor connection retries exceeded".to_string()))
    }

    /// Try to connect once through Tor
    async fn try_connect(&self, target: &str, port: u16) -> Result<TcpStream> {
        // Connect to SOCKS5 proxy
        let proxy_stream = timeout(
            self.config.connection_timeout,
            TcpStream::connect(self.config.socks_proxy)
        ).await
        .map_err(|_| GdkError::Network("Tor proxy connection timeout".to_string()))?
        .map_err(|e| GdkError::Network(format!("Failed to connect to Tor proxy: {}", e)))?;

        // Perform SOCKS5 handshake
        let mut stream = self.socks5_handshake(proxy_stream, target, port).await?;
        
        Ok(stream)
    }

    /// Perform SOCKS5 handshake
    async fn socks5_handshake(&self, mut stream: TcpStream, target: &str, port: u16) -> Result<TcpStream> {
        // Step 1: Authentication negotiation
        stream.write_all(&[SOCKS5_VERSION, 1, SOCKS5_NO_AUTH]).await
            .map_err(|e| GdkError::Network(format!("SOCKS5 auth negotiation failed: {}", e)))?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await
            .map_err(|e| GdkError::Network(format!("SOCKS5 auth response failed: {}", e)))?;

        if response[0] != SOCKS5_VERSION {
            return Err(GdkError::Network("Invalid SOCKS5 version".to_string()));
        }

        if response[1] != SOCKS5_NO_AUTH {
            return Err(GdkError::Network("SOCKS5 authentication required but not supported".to_string()));
        }

        // Step 2: Connection request
        let mut request = Vec::new();
        request.push(SOCKS5_VERSION);
        request.push(SOCKS5_CONNECT);
        request.push(0); // Reserved

        // Determine address type and encode target
        if target.ends_with(".onion") {
            // Onion address
            request.push(SOCKS5_DOMAIN);
            request.push(target.len() as u8);
            request.extend_from_slice(target.as_bytes());
        } else if let Ok(ip) = target.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(ipv4) => {
                    request.push(SOCKS5_IPV4);
                    request.extend_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    request.push(SOCKS5_IPV6);
                    request.extend_from_slice(&ipv6.octets());
                }
            }
        } else {
            // Domain name
            request.push(SOCKS5_DOMAIN);
            request.push(target.len() as u8);
            request.extend_from_slice(target.as_bytes());
        }

        // Add port
        request.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&request).await
            .map_err(|e| GdkError::Network(format!("SOCKS5 connection request failed: {}", e)))?;

        // Read response
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).await
            .map_err(|e| GdkError::Network(format!("SOCKS5 connection response failed: {}", e)))?;

        if response[0] != SOCKS5_VERSION {
            return Err(GdkError::Network("Invalid SOCKS5 response version".to_string()));
        }

        if response[1] != 0 {
            let error_msg = match response[1] {
                1 => "General SOCKS server failure",
                2 => "Connection not allowed by ruleset",
                3 => "Network unreachable",
                4 => "Host unreachable",
                5 => "Connection refused",
                6 => "TTL expired",
                7 => "Command not supported",
                8 => "Address type not supported",
                _ => "Unknown SOCKS error",
            };
            return Err(GdkError::Network(format!("SOCKS5 error: {}", error_msg)));
        }

        // Read the bound address (we don't need it, but must read it)
        match response[3] {
            SOCKS5_IPV4 => {
                let mut addr = [0u8; 6]; // 4 bytes IP + 2 bytes port
                stream.read_exact(&mut addr).await
                    .map_err(|e| GdkError::Network(format!("Failed to read SOCKS5 bound address: {}", e)))?;
            }
            SOCKS5_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await
                    .map_err(|e| GdkError::Network(format!("Failed to read SOCKS5 domain length: {}", e)))?;
                let mut addr = vec![0u8; len[0] as usize + 2]; // domain + 2 bytes port
                stream.read_exact(&mut addr).await
                    .map_err(|e| GdkError::Network(format!("Failed to read SOCKS5 bound address: {}", e)))?;
            }
            SOCKS5_IPV6 => {
                let mut addr = [0u8; 18]; // 16 bytes IP + 2 bytes port
                stream.read_exact(&mut addr).await
                    .map_err(|e| GdkError::Network(format!("Failed to read SOCKS5 bound address: {}", e)))?;
            }
            _ => {
                return Err(GdkError::Network("Invalid SOCKS5 address type in response".to_string()));
            }
        }

        Ok(stream)
    }

    /// Initialize Tor control connection
    pub async fn init_control_connection(&self) -> Result<()> {
        if let Some(control_addr) = self.config.control_port {
            let control_conn = TorControlConnection::new(control_addr, self.config.control_password.clone()).await?;
            *self.control_connection.lock().await = Some(control_conn);
        }
        Ok(())
    }

    /// Create a new circuit
    pub async fn new_circuit(&self) -> Result<String> {
        let mut control_conn = self.control_connection.lock().await;
        if let Some(ref mut conn) = *control_conn {
            let circuit_id = conn.new_circuit().await?;
            
            let circuit = TorCircuit {
                id: circuit_id.clone(),
                created_at: Instant::now(),
                path: Vec::new(), // Would be populated by parsing control responses
                status: CircuitStatus::Building,
            };
            
            self.circuits.lock().await.insert(circuit_id.clone(), circuit);
            
            let mut stats = self.stats.write().await;
            stats.circuits_created += 1;
            
            Ok(circuit_id)
        } else {
            Err(GdkError::Network("Tor control connection not available".to_string()))
        }
    }

    /// Rotate circuits
    async fn rotate_circuits(
        circuits: &Arc<Mutex<HashMap<String, TorCircuit>>>,
        control_conn: &Arc<Mutex<Option<TorControlConnection>>>,
    ) -> Result<()> {
        let mut control_conn = control_conn.lock().await;
        if let Some(ref mut conn) = *control_conn {
            // Close old circuits
            let circuit_ids: Vec<String> = {
                let circuits_guard = circuits.lock().await;
                circuits_guard.keys().cloned().collect()
            };
            
            for circuit_id in circuit_ids {
                if let Err(e) = conn.close_circuit(&circuit_id).await {
                    log::warn!("Failed to close circuit {}: {}", circuit_id, e);
                }
            }
            
            // Clear circuit list
            circuits.lock().await.clear();
            
            log::info!("Rotated Tor circuits");
        }
        
        Ok(())
    }

    /// Get connection statistics
    pub async fn get_stats(&self) -> TorStats {
        self.stats.read().await.clone()
    }

    /// Check if target is an onion service
    pub fn is_onion_service(target: &str) -> bool {
        target.ends_with(".onion")
    }

    /// Get preferred onion endpoint if available
    pub fn get_onion_endpoint(&self, service_name: &str) -> Option<&String> {
        self.config.onion_endpoints.iter()
            .find(|endpoint| endpoint.contains(service_name))
    }

    pub async fn update_stats_success(&self, target: &str) {
        let mut stats = self.stats.write().await;
        stats.connections_established += 1;
        
        if Self::is_onion_service(target) {
            stats.onion_connections += 1;
        } else {
            stats.clearnet_connections += 1;
        }
    }

    pub async fn update_stats_failure(&self) {
        let mut stats = self.stats.write().await;
        stats.connections_failed += 1;
    }
}

/// Tor control connection for circuit management
pub struct TorControlConnection {
    stream: TcpStream,
    authenticated: bool,
}

impl TorControlConnection {
    /// Create new control connection
    pub async fn new(control_addr: SocketAddr, password: Option<String>) -> Result<Self> {
        let stream = TcpStream::connect(control_addr).await
            .map_err(|e| GdkError::Network(format!("Failed to connect to Tor control port: {}", e)))?;

        let mut conn = Self {
            stream,
            authenticated: false,
        };

        // Authenticate if password is provided
        if let Some(password) = password {
            conn.authenticate(&password).await?;
        } else {
            // Try null authentication
            conn.authenticate("").await?;
        }

        Ok(conn)
    }

    /// Authenticate with Tor control port
    async fn authenticate(&mut self, password: &str) -> Result<()> {
        let auth_cmd = if password.is_empty() {
            "AUTHENTICATE\r\n".to_string()
        } else {
            format!("AUTHENTICATE \"{}\"\r\n", password)
        };

        self.stream.write_all(auth_cmd.as_bytes()).await
            .map_err(|e| GdkError::Network(format!("Failed to send auth command: {}", e)))?;

        let mut response = vec![0u8; 1024];
        let n = self.stream.read(&mut response).await
            .map_err(|e| GdkError::Network(format!("Failed to read auth response: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response[..n]);
        if response_str.starts_with("250") {
            self.authenticated = true;
            Ok(())
        } else {
            Err(GdkError::Network(format!("Tor authentication failed: {}", response_str)))
        }
    }

    /// Create a new circuit
    pub async fn new_circuit(&mut self) -> Result<String> {
        if !self.authenticated {
            return Err(GdkError::Network("Not authenticated with Tor control port".to_string()));
        }

        let circuit_cmd = "EXTENDCIRCUIT 0\r\n";
        self.stream.write_all(circuit_cmd.as_bytes()).await
            .map_err(|e| GdkError::Network(format!("Failed to send circuit command: {}", e)))?;

        let mut response = vec![0u8; 1024];
        let n = self.stream.read(&mut response).await
            .map_err(|e| GdkError::Network(format!("Failed to read circuit response: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response[..n]);
        if let Some(circuit_line) = response_str.lines().find(|line| line.starts_with("250 EXTENDED")) {
            // Parse circuit ID from response like "250 EXTENDED 123"
            if let Some(circuit_id) = circuit_line.split_whitespace().nth(2) {
                Ok(circuit_id.to_string())
            } else {
                Err(GdkError::Network("Failed to parse circuit ID".to_string()))
            }
        } else {
            Err(GdkError::Network(format!("Failed to create circuit: {}", response_str)))
        }
    }

    /// Close a circuit
    pub async fn close_circuit(&mut self, circuit_id: &str) -> Result<()> {
        if !self.authenticated {
            return Err(GdkError::Network("Not authenticated with Tor control port".to_string()));
        }

        let close_cmd = format!("CLOSECIRCUIT {}\r\n", circuit_id);
        self.stream.write_all(close_cmd.as_bytes()).await
            .map_err(|e| GdkError::Network(format!("Failed to send close circuit command: {}", e)))?;

        let mut response = vec![0u8; 1024];
        let n = self.stream.read(&mut response).await
            .map_err(|e| GdkError::Network(format!("Failed to read close circuit response: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response[..n]);
        if response_str.starts_with("250") {
            Ok(())
        } else {
            Err(GdkError::Network(format!("Failed to close circuit: {}", response_str)))
        }
    }

    /// Get circuit information
    pub async fn get_circuit_info(&mut self, circuit_id: &str) -> Result<TorCircuit> {
        if !self.authenticated {
            return Err(GdkError::Network("Not authenticated with Tor control port".to_string()));
        }

        let info_cmd = format!("GETINFO circuit-status\r\n");
        self.stream.write_all(info_cmd.as_bytes()).await
            .map_err(|e| GdkError::Network(format!("Failed to send circuit info command: {}", e)))?;

        let mut response = vec![0u8; 4096];
        let n = self.stream.read(&mut response).await
            .map_err(|e| GdkError::Network(format!("Failed to read circuit info response: {}", e)))?;

        let response_str = String::from_utf8_lossy(&response[..n]);
        
        // Parse circuit information from response
        // This is a simplified implementation - real parsing would be more complex
        for line in response_str.lines() {
            if line.contains(circuit_id) {
                return Ok(TorCircuit {
                    id: circuit_id.to_string(),
                    created_at: Instant::now(), // Would parse from response
                    path: Vec::new(), // Would parse relay path from response
                    status: CircuitStatus::Built, // Would parse actual status
                });
            }
        }

        Err(GdkError::Network(format!("Circuit {} not found", circuit_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tor_config_defaults() {
        let config = TorConfig::default();
        
        assert_eq!(config.socks_proxy.port(), 9050);
        assert_eq!(config.control_port.unwrap().port(), 9051);
        assert_eq!(config.enable_circuit_rotation, true);
        assert_eq!(config.connection_timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.enable_onion_services, true);
    }

    #[test]
    fn test_is_onion_service() {
        assert!(TorManager::is_onion_service("example.onion"));
        assert!(TorManager::is_onion_service("3g2upl4pq6kufc4m.onion"));
        assert!(!TorManager::is_onion_service("example.com"));
        assert!(!TorManager::is_onion_service("192.168.1.1"));
    }

    #[test]
    fn test_circuit_status() {
        let circuit = TorCircuit {
            id: "123".to_string(),
            created_at: Instant::now(),
            path: vec!["relay1".to_string(), "relay2".to_string()],
            status: CircuitStatus::Built,
        };
        
        assert_eq!(circuit.status, CircuitStatus::Built);
        assert_eq!(circuit.path.len(), 2);
    }

    #[tokio::test]
    async fn test_tor_manager_creation() {
        let config = TorConfig::default();
        let manager = TorManager::new(config);
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.connections_established, 0);
        assert_eq!(stats.circuits_created, 0);
    }

    #[tokio::test]
    async fn test_tor_stats_update() {
        let config = TorConfig::default();
        let manager = TorManager::new(config);
        
        manager.update_stats_success("example.onion").await;
        let stats = manager.get_stats().await;
        
        assert_eq!(stats.connections_established, 1);
        assert_eq!(stats.onion_connections, 1);
        assert_eq!(stats.clearnet_connections, 0);
    }

    #[test]
    fn test_socks5_constants() {
        assert_eq!(SOCKS5_VERSION, 0x05);
        assert_eq!(SOCKS5_NO_AUTH, 0x00);
        assert_eq!(SOCKS5_CONNECT, 0x01);
        assert_eq!(SOCKS5_DOMAIN, 0x03);
    }
}