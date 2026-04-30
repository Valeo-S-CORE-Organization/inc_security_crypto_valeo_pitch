// *******************************************************************************
// Copyright (c) 2025 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// <https://www.apache.org/licenses/LICENSE-2.0>
//
// SPDX-License-Identifier: Apache-2.0
// *******************************************************************************
use std::fs;
use std::io::Write as _;

use super::locks::LOCK_FILE_FD;
use super::models::StoredState;
use super::path::storage_path;

pub fn load_state() -> Option<StoredState> {
    let path = storage_path();
    let data = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn save_state(state: &StoredState) -> Result<(), String> {
    let path = storage_path();
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));

    fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    let lock_path = path.with_extension("lock");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("open lock file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd as _;
        use std::sync::atomic::Ordering;
        let fd = lock_file.as_raw_fd();
        LOCK_FILE_FD.store(fd, Ordering::Release);
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if ret != 0 {
            return Err(format!("flock exclusive failed: {}", std::io::Error::last_os_error()));
        }
    }

    let json = serde_json::to_string_pretty(state).map_err(|e| format!("serialize: {e}"))?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| format!("create tempfile: {e}"))?;
    tmp.write_all(json.as_bytes()).map_err(|e| format!("write tempfile: {e}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod tempfile 0600: {e}"))?;
    }

    tmp.as_file().sync_all().map_err(|e| format!("fsync tempfile: {e}"))?;
    tmp.persist(&path).map_err(|e| format!("persist (rename): {e}"))?;

    let dir = fs::File::open(parent).map_err(|e| format!("open parent dir: {e}"))?;
    dir.sync_all().map_err(|e| format!("fsync parent dir: {e}"))?;

    drop(lock_file);
    #[cfg(unix)]
    {
        use std::sync::atomic::Ordering;
        LOCK_FILE_FD.store(-1, Ordering::Release);
    }
    Ok(())
}

pub fn delete_storage() -> Result<(), String> {
    let path = storage_path();
    if path.exists() {
        fs::remove_file(&path).map_err(|e| format!("delete: {e}"))?;
    }
    Ok(())
}
