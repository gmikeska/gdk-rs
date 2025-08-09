use gdk_rs::{
    protocol::{
        Addressee, CreateTransactionParams, GetAssetsParams, GetTransactionsParams,
        GetUnspentOutputsParams, LoginCredentials,
    },
    types::{ConnectParams, GdkConfig},
    Session,
};

mod common;

async fn get_connected_session() -> (Session, std::net::SocketAddr) {
    let server_addr = common::start_mock_server().await;
    let config = GdkConfig::default();
    let mut session = Session::new(config);
    let connect_params = ConnectParams {
        chain_id: "localtest".to_string(),
        user_agent: None,
        use_proxy: false,
        proxy: None,
        tor_enabled: false,
    };
    let url = format!("ws://{}/v2/ws", server_addr);
    session.connect(&connect_params, &url).await.unwrap();
    (session, server_addr)
}

#[tokio::test]
async fn test_session_connect() {
    let (_session, _addr) = get_connected_session().await;
}

#[tokio::test]
async fn test_session_login() {
    let (session, _) = get_connected_session().await;
    let creds = LoginCredentials {
        mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title".to_string(),
        password: None,
        bip39_passphrase: None,
    };
    let result = session.login(&creds).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().wallet_hash_id, "mock_wallet_hash_id");
}

#[tokio::test]
async fn test_get_subaccounts() {
    let (session, _) = get_connected_session().await;
    let result = session.get_subaccounts().await;
    assert!(result.is_ok());
    assert!(result.unwrap().subaccounts.is_empty());
}

#[tokio::test]
async fn test_get_transactions() {
    let (session, _) = get_connected_session().await;
    let params = GetTransactionsParams { subaccount: 0, first: 0, count: 10 };
    let result = session.get_transactions(&params).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[tokio::test]
async fn test_get_unspent_outputs() {
    let (session, _) = get_connected_session().await;
    let params = GetUnspentOutputsParams { subaccount: 0, num_confs: 0 };
    let result = session.get_unspent_outputs(&params).await;
    assert!(result.is_ok());
    assert!(result.unwrap().unspent_outputs.is_empty());
}

#[tokio::test]
async fn test_get_assets() {
    let (session, _) = get_connected_session().await;
    let params = GetAssetsParams { details: true };
    let result = session.get_assets(&params).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().assets.len(), 1);
}

#[tokio::test]
async fn test_create_and_sign_transaction() {
    let (session, _) = get_connected_session().await;

    // Login to create the wallet
    let creds = LoginCredentials {
        mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title".to_string(),
        password: None,
        bip39_passphrase: None,
    };
    session.login(&creds).await.unwrap();

    // Create
    let mut params = CreateTransactionParams {
        addressees: vec![],
        fee_rate: 5,
        subaccount: 0,
    };
    let create_result = session.create_transaction(&mut params).await;
    assert!(create_result.is_ok(), "create_transaction failed: {:?}", create_result.err());
    let pset = create_result.unwrap();

    // Sign
    let sign_result = session.sign_transaction(&pset).await;
    assert!(sign_result.is_ok(), "sign_transaction failed: {:?}", sign_result.err());
}
