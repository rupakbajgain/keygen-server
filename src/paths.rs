use std::fs;
use std::path::PathBuf;

pub fn get_master_key_path() -> PathBuf {
    let mut path = home::home_dir().expect("Could not find home directory");
    path.push(".base0");
    if !path.exists() {
        fs::create_dir_all(&path).expect("Failed to create directory");
    }
    path.push("master.key");
    path
}

pub fn get_socket_path() -> PathBuf {
    let uid = unsafe { libc::getuid() };
    let base_path = PathBuf::from(format!("/run/user/{}/mfs", uid));
    if !base_path.exists() {
        fs::create_dir_all(&base_path).expect("Failed to create socket dir");
    }
    base_path.join("keyserver.socket")
}
