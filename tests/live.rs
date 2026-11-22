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
    let (Ok(url), Ok(password)) = (std::env::var("HEM_URL"), std::env::var("HEM_PASSWORD")) else {
        eprintln!("skipped: HEM_URL and HEM_PASSWORD not set");
        return;
    };
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

/// `auth = "remote+password"`: the phone is asked first; "Use password" stops
/// asking it (the request is withdrawn) and the waiting sign takes the token
/// of the password unlock. Lock during that wait ends the sign unsigned.
/// The paired phone gets two requests that are withdrawn within seconds, so
/// this runs only with HEM_PHONE=1 as well.
#[tokio::test]
async fn phone_first_then_password() {
    let (Ok(url), Ok(password), Ok(_)) =
        (std::env::var("HEM_URL"), std::env::var("HEM_PASSWORD"), std::env::var("HEM_PHONE"))
    else {
        eprintln!("skipped: HEM_URL, HEM_PASSWORD and HEM_PHONE not set");
        return;
    };
    let hem = Hem::new(&url, HemOptions::default()).unwrap();
    let tok = hem.authorize_password(Some(&password), ["keymgmt:search"], AuthOptions::default()).await.unwrap();
    let search = SearchOptions { key_type: Some("ED25519".into()), ..Default::default() };
    let Some(found) = hem.search_keys_all(Some(&tok), TEST_DESCR, search).await.unwrap().into_iter().next() else {
        eprintln!("skipped: no test key yet (agent_lists_and_signs creates it)");
        return;
    };
    let tok = hem.authorize_password(None, key_scopes(&[&found.kid]), AuthOptions::default()).await.unwrap();
    let key = load_key(&hem, &tok, &found.kid).await.unwrap();

    let auth = Auth::Remote { uv: None, timeout: std::time::Duration::from_secs(60), password: Some(60) };
    let agent = HemAgent::new(Arc::new(Hem::new(&url, HemOptions::default()).unwrap()), vec![key.clone()], auth);
    let mut status = agent.subscribe();
    assert_eq!(status.borrow().auth, "remote+password");
    let req = SignRequest { credential: PublicCredential::Key(key.public.clone()), data: b"phone first".to_vec(), flags: 0 };

    // 1. The phone is asked; Use password; the password unlock signs.
    let mut signer = agent.clone();
    let sign = tokio::spawn({
        let req = req.clone();
        async move { signer.sign(req).await }
    });
    status.wait_for(|s| s.pending.as_ref().is_some_and(|p| !p.password)).await.unwrap();
    agent.use_password().await.unwrap();
    status.wait_for(|s| s.pending.as_ref().is_some_and(|p| p.password)).await.unwrap();
    agent.unlock_with_password(&password).await.unwrap();
    let sig = sign.await.unwrap().expect("signed with the password's token");
    assert_eq!(sig.algorithm(), Algorithm::Ed25519);
    let s = status.borrow().clone();
    assert_eq!((s.state.as_str(), s.pending, s.last.map(|l| l.result)), ("ready", None, Some("signed".into())));

    // 2. Lock while waiting for the password: not signed, at once.
    agent.lock().await;
    let mut signer = agent.clone();
    let sign = tokio::spawn({
        let req = req.clone();
        async move { signer.sign(req).await }
    });
    status.wait_for(|s| s.pending.as_ref().is_some_and(|p| !p.password)).await.unwrap();
    agent.use_password().await.unwrap();
    status.wait_for(|s| s.pending.as_ref().is_some_and(|p| p.password)).await.unwrap();
    agent.lock().await;
    let started = std::time::Instant::now();
    assert!(sign.await.unwrap().is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(status.borrow().last.as_ref().map(|l| l.result.as_str()), Some("locked"));
}
