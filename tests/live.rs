//! The agent end to end against a real (or simulated) HEM, through the real
//! transport (named pipe / unix socket) and an agent-protocol client.
//! Skipped unless HEM_URL and HEM_PASSWORD are set:
//!
//!   HEM_URL=https://ssh-agent-tester.playground.ence.do HEM_PASSWORD=... cargo test --test live

use std::sync::Arc;

use hem_sdk::{AuthOptions, CreateOptions, Hem, HemOptions, SearchOptions};
use hem_ssh_agent::{key_scopes, listen, load_key, Auth, HemAgent};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::{PublicCredential, SignRequest};
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::Algorithm;

/// Description of the one test key; found again on every run, created only once.
const TEST_DESCR: &[u8] = b"hem-ssh-agent-test";

#[tokio::test]
async fn agent_lists_and_signs() {
    let (Ok(url), Ok(password)) = (std::env::var("HEM_URL"), std::env::var("HEM_PASSWORD")) else { return };
    let hem = Arc::new(Hem::new(&url, HemOptions::default()).unwrap());

    // The test key: found by description, created on the first run only.
    let tok = hem
        .authorize_password(Some(&password), ["keymgmt:search", "keymgmt:gen"], AuthOptions::default())
        .await
        .unwrap();
    let search = SearchOptions { key_type: Some("ED25519".into()), ..Default::default() };
    let kid = match hem.search_keys_all(Some(&tok), TEST_DESCR, search).await.unwrap().into_iter().next() {
        Some(k) => k.kid,
        None => {
            let opts = CreateOptions { descr: Some(TEST_DESCR.to_vec()), ..Default::default() };
            hem.create_key_pair(&tok, "hem-ssh-agent live test", "ED25519", opts).await.unwrap().kid
        }
    };

    // The public key, as `pubkey` prints it for the configuration file.
    let tok = hem.authorize_password(None, key_scopes(&[&kid]), AuthOptions::default()).await.unwrap();
    let key = load_key(&hem, &tok, &kid).await.unwrap();
    let KeyData::Ed25519(Ed25519PublicKey(pk)) = key.public.clone() else { panic!("not Ed25519") };
    assert!(key.openssh().starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"));

    // A fresh device handle for the agent: nothing remembered, starts locked.
    let agent_hem = Arc::new(Hem::new(&url, HemOptions::default()).unwrap());
    #[cfg(windows)]
    let address = format!(r"\\.\pipe\hem-ssh-agent-test-{}", std::process::id());
    #[cfg(unix)]
    let address = std::env::temp_dir().join(format!("hem-ssh-agent-test-{}.sock", std::process::id())).to_string_lossy().into_owned();
    let listener = listen::bind(&address).await.unwrap();
    tokio::spawn(listen::serve(listener, HemAgent::new(agent_hem, vec![key.clone()], Auth::Password { ttl: 60 })));

    #[cfg(windows)]
    let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(&address).unwrap();
    #[cfg(unix)]
    let stream = tokio::net::UnixStream::connect(&address).await.unwrap();
    let mut client = Client::new(stream);

    // Locked: no keys, no signature; a wrong password does not unlock.
    assert!(client.request_identities().await.unwrap().is_empty());
    let req = SignRequest { credential: PublicCredential::Key(key.public.clone()), data: b"x".to_vec(), flags: 0 };
    assert!(client.sign(req).await.is_err());
    assert!(client.unlock("not the password".into()).await.is_err());
    assert!(client.request_identities().await.unwrap().is_empty());

    // `ssh-add -X` with the HEM password.
    client.unlock(password.clone()).await.unwrap();
    let ids = client.request_identities().await.unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].credential, PublicCredential::Key(key.public.clone()));
    assert_eq!(ids[0].comment, key.comment);

    // An SSH user-auth blob is a few hundred bytes; any bytes do for the test.
    let data = b"hem-ssh-agent live test: data to sign".repeat(8);
    let sig = client
        .sign(SignRequest { credential: PublicCredential::Key(key.public.clone()), data: data.clone(), flags: 0 })
        .await
        .unwrap();
    assert_eq!(sig.algorithm(), Algorithm::Ed25519);

    // Independent check, as an SSH server would do it.
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).unwrap();
    let s = ed25519_dalek::Signature::from_bytes(sig.as_bytes().try_into().unwrap());
    vk.verify_strict(&data, &s).expect("signature verifies with ed25519-dalek");

    // A key the agent does not serve: FAILURE.
    let other = KeyData::Ed25519(Ed25519PublicKey([7u8; 32]));
    assert!(client
        .sign(SignRequest { credential: PublicCredential::Key(other), data: data.clone(), flags: 0 })
        .await
        .is_err());

    // `ssh-add -x`: locked again, the derived key dropped.
    client.lock(String::new()).await.unwrap();
    assert!(client.request_identities().await.unwrap().is_empty());
    let req = SignRequest { credential: PublicCredential::Key(key.public.clone()), data, flags: 0 };
    assert!(client.sign(req).await.is_err());

    #[cfg(unix)]
    let _ = std::fs::remove_file(&address);
}
