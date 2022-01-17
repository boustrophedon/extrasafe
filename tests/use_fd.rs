use extrasafe::*;
use extrasafe::builtins::SystemIO;

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};


#[test]
fn allow_only_specific_files() {
    // create tempdir, write file
    let dir = tempfile::tempdir().unwrap();
    let mut path = dir.path().to_path_buf();
    path.push("write_to_me.txt");
    
    let mut file = File::create(&path).unwrap();
    file.write_all(b"hello world").unwrap();
    file.sync_all().unwrap();
    drop(file);

    // open again, pass to safety context
    let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();

    let res = SafetyContext::new()
        .enable(SystemIO::nothing()
            .allow_stdout()
            .allow_stderr()
            .allow_file_read(&file)
            .allow_file_write(&file)
            .allow_close()
        ).unwrap()
        .apply_to_current_thread();
    assert!(res.is_ok(), "extrasafe failed {:?}", res.unwrap_err());


    // read data from file
    let mut buf = String::new();
    let res = file.read_to_string(&mut buf);
    assert!(res.is_ok(), "Failed to read back string from file: {:?}", res.unwrap_err());
    assert_eq!(buf, "hello world");

    // write data to file
    let res = file.write_all(b" appended to");
    assert!(res.is_ok(), "Failed to write to file: {:?}", res.unwrap_err());

    // read new data back from file
    file.rewind().unwrap();

    let mut buf = String::new();
    let res = file.read_to_string(&mut buf);
    assert!(res.is_ok(), "Failed to read back string from file: {:?}", res.unwrap_err());
    assert_eq!(buf, "hello world appended to");


    // check that after we close it, we cannot open it again (because that creates a new fd)
    drop(file);

    let res = File::open(&path);
    assert!(res.is_err(), "opening file suceeded incorrectly");
}
