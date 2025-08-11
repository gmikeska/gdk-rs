use gdk_rs::*;
use gdk_rs::utils::logging::LogLevel;
use tempfile::TempDir;

mod common;

#[tokio::test]
async fn test_minimal_hang_debug() {
    println!("Test starting");
    
    // Test 1: GDK init
    let temp_dir = TempDir::new().unwrap();
    let config = GdkConfig {
        data_dir: Some(temp_dir.path().to_path_buf()),
        tor_dir: None,
        registry_dir: None,
        log_level: Some(LogLevel::Debug),
        with_shutdown: false,
    };
    
    println!("Calling init");
    init(&config).unwrap();
    println!("Init completed");
    
    // Test 2: Mock server
    println!("Starting mock server");
    let mock_addr = common::start_mock_server().await;
    println!("Mock server started at: {}", mock_addr);
    
    // Test 3: Session creation
    println!("Creating session");
    let session = Session::new(config);
    println!("Session created");
    
    println!("Test completed");
}

#[tokio::test]
async fn test_mock_server_only() {
    println!("Starting mock server test");
    let mock_addr = common::start_mock_server().await;
    println!("Mock server started at: {}", mock_addr);
    
    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    println!("Test completed");
}

#[tokio::test]
async fn test_connection_hang() {
    use gdk_rs::types::*;
    
    println!("Starting connection test");
    
    let temp_dir = TempDir::new().unwrap();
    let config = GdkConfig {
        data_dir: Some(temp_dir.path().to_path_buf()),
        tor_dir: None,
        registry_dir: None,
        log_level: Some(LogLevel::Debug),
        with_shutdown: false,
    };
    
    println!("Initializing GDK");
    init(&config).unwrap();
    
    println!("Creating session");
    let mut session = Session::new(config);
    
    println!("Starting mock server");
    let mock_addr = common::start_mock_server().await;
    let mock_url = format!("ws://{}/v2/ws", mock_addr);
    println!("Mock server URL: {}", mock_url);
    
    let network_params = ConnectParams {
        name: Some("testnet".to_string()),
        proxy: None,
        use_tor: false,
        tor_enabled: false,
        use_proxy: false,
        user_agent: Some("gdk-rs-test/1.0".to_string()),
        spv_enabled: false,
        min_fee_rate: Some(1000),
        electrum_url: None,
        electrum_tls: false,
        chain_id: "bitcoin".to_string(),
    };
    
    let urls: Vec<String> = vec![mock_url];
    
    println!("Attempting to connect...");
    match session.connect(&network_params, &urls).await {
        Ok(_) => println!("Connected successfully"),
        Err(e) => println!("Connection failed: {}", e),
    }
    
    println!("Test completed");
}
