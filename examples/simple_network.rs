//! Simple example showing how network requests can be made with extrasafe, including using
//! landlock to allow access to ssl certificates and dns files
//!
//! When using rustls (with the webpki-certs crate), the `allow_ssl_files()` call can be omitted as
//! the root certificate store is included in the binary. See the `Cargo.toml` configuration for
//! musl.

use extrasafe::builtins::{danger_zone::Threads, Networking, SystemIO};
use extrasafe::*;

fn main() {
    // do as much setup before enabling extrasafe so we can enable the least amount of syscalls
    let runtime = tokio::runtime::Builder::new_current_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let client = reqwest::Client::new();

    let ctx = SafetyContext::new()
        .enable(
            Networking::nothing()
                // Necessary for DNS
                .allow_start_udp_servers()
                .yes_really()
                .allow_start_tcp_clients(),
        )
        .unwrap()
        // hyper (via reqwest) seems to want to spawn a separate blocking thread to do DNS and it
        // doesn't seem like it can be preallocated easily.
        // TODO: investigate using runtime::Builder::thread_keep_alive and max_blocking_threads to
        // effectively preallocate by then just doing `block_on(|| ())`
        .enable(Threads::nothing().allow_create())
        .unwrap();
    // allow access to dns and ssl files
    // note that allowing ssl file access isn't necessary if using rustls with webpki-certs
    // and allowing the dns files isn't strictly necessary either depending on various system
    // configurations
    #[cfg(feature = "landlock")]
    let ctx = ctx
        .enable(SystemIO::nothing().allow_dns_files().allow_ssl_files())
        .unwrap();
    #[cfg(not(feature = "landlock"))]
    let ctx = ctx
        .enable(
            SystemIO::nothing()
                .allow_open_readonly()
                .allow_read()
                .allow_metadata()
                .allow_close(),
        )
        .unwrap();

    ctx.apply_to_current_thread().unwrap();

    // make an http request
    runtime.block_on(async {
        // Show that we can resolve dns and do ssl. Data returned isn't checked or used anywhere,
        // we just get it and print it out.
        let resp = client.get("https://example.org").send().await.unwrap();
        let res = resp.text().await;
        assert!(
            res.is_ok(),
            "failed getting example.org response: {:?}",
            res.unwrap_err()
        );
        let text = res.unwrap();
        println!(
            "first 10 bytes of response from example.org {}",
            &text[..10]
        );
    });
}

#[test]
fn run_main() {
    main();
}
