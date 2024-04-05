#![cfg(feature = "isolate")]
use extrasafe::isolate::Isolate;
use std::collections::HashMap;
use std::path::PathBuf;

const EXAMPLE_ISOLATE: &str = "user guide isolate";

/// The function that ultimately runs inside the Isolate
fn do_cool_thing() {
    println!("I'm going to read some files from /cooldir and do cool stuff with it!");
    // TODO: do cool stuff with the files in /cooldir
}

/// Isolate configuration that happens when the program is re-executed after `Isolate::run`
fn setup_isolate(name: &'static str) -> Isolate {
    let path = std::env::var("COOL_DIRECTORY").unwrap();
    let path = PathBuf::from(path);
    Isolate::new(name, do_cool_thing)
        // This will mount /a/b/c from the parent into /cooldir in the child,
        // but not until after entering the namespace.
        .add_bind_mount(path, "/cooldir")
        // Limit the amount of data that can be written to the filesystem the
        // Isolate lives in.
        .set_rootfs_size(1)
}

fn main() {
    // Once the Isolate::run call is made, this will run the setup function,
    // enter the namespace and call the the function provided. The first time the program runs,
    // this code will be ignored.
    Isolate::main_hook(EXAMPLE_ISOLATE, setup_isolate);

    // ... somewhere later in the program

    let env_vars = HashMap::from([("COOL_DIRECTORY".to_string(), "/".to_string())]);

    // `Isolate::run` returns a normal `std::process::Output`
    let output = Isolate::run(EXAMPLE_ISOLATE, &env_vars).unwrap();

    assert!(output.status.success());
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
}
