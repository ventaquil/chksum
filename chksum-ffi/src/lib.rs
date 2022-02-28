use std::ffi::CString;
use std::os::raw::c_char;
use std::{ptr, slice};

use chksum::hash::{md5, sha1};

#[allow(clippy::let_and_return)]
#[no_mangle]
pub extern "C" fn chksum_hash_md5_new() -> *mut md5::State<u32> {
    let state = md5::State::new();
    let state = Box::new(state);
    let state = Box::into_raw(state);
    state
}

#[no_mangle]
pub unsafe extern "C" fn chksum_hash_md5_update(hash: *mut md5::State<u32>, data: *const u8, length: usize) -> usize {
    if data.is_null() || (length < md5::BLOCK_LENGTH_BYTES) {
        return 0;
    }
    match hash.as_mut() {
        Some(hash) => {
            for offset in 0..(length / md5::BLOCK_LENGTH_BYTES) {
                let block = data.add(offset);
                let block = slice::from_raw_parts(block, md5::BLOCK_LENGTH_BYTES);
                let block = [
                    u32::from_le_bytes([block[0x00], block[0x01], block[0x02], block[0x03]]),
                    u32::from_le_bytes([block[0x04], block[0x05], block[0x06], block[0x07]]),
                    u32::from_le_bytes([block[0x08], block[0x09], block[0x0A], block[0x0B]]),
                    u32::from_le_bytes([block[0x0C], block[0x0D], block[0x0E], block[0x0F]]),
                    u32::from_le_bytes([block[0x10], block[0x11], block[0x12], block[0x13]]),
                    u32::from_le_bytes([block[0x14], block[0x15], block[0x16], block[0x17]]),
                    u32::from_le_bytes([block[0x18], block[0x19], block[0x1A], block[0x1B]]),
                    u32::from_le_bytes([block[0x1C], block[0x1D], block[0x1E], block[0x1F]]),
                    u32::from_le_bytes([block[0x20], block[0x21], block[0x22], block[0x23]]),
                    u32::from_le_bytes([block[0x24], block[0x25], block[0x26], block[0x27]]),
                    u32::from_le_bytes([block[0x28], block[0x29], block[0x2A], block[0x2B]]),
                    u32::from_le_bytes([block[0x2C], block[0x2D], block[0x2E], block[0x2F]]),
                    u32::from_le_bytes([block[0x30], block[0x31], block[0x32], block[0x33]]),
                    u32::from_le_bytes([block[0x34], block[0x35], block[0x36], block[0x37]]),
                    u32::from_le_bytes([block[0x38], block[0x39], block[0x3A], block[0x3B]]),
                    u32::from_le_bytes([block[0x3C], block[0x3D], block[0x3E], block[0x3F]]),
                ];
                hash.update(block);
            }
            length - (length % md5::BLOCK_LENGTH_BYTES)
        },
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn chksum_hash_md5_digest(hash: *const md5::State<u32>) -> *mut u8 {
    match hash.as_ref() {
        Some(hash) => {
            let digest = hash.digest();
            let digest: md5::Digest<u8> = digest.into();
            let digest: [u8; md5::DIGEST_LENGTH_BYTES] = digest.into();
            let digest = Box::new(digest);
            Box::into_raw(digest) as *mut u8
        },
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn chksum_hash_md5_hexdigest(hash: *const md5::State<u32>) -> *mut c_char {
    match hash.as_ref() {
        Some(hash) => {
            let digest = hash.digest();
            let digest: md5::Digest<u8> = digest.into();
            let digest = format!("{digest:x}");
            let digest = CString::new(digest).expect("CString::new failed");
            digest.into_raw()
        },
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn chksum_hash_md5_drop(hash: *mut md5::State<u32>) {
    drop(Box::from_raw(hash));
}

#[allow(clippy::let_and_return)]
#[no_mangle]
pub extern "C" fn chksum_hash_sha1_new() -> *mut sha1::State<u32> {
    let state = sha1::State::new();
    let state = Box::new(state);
    let state = Box::into_raw(state);
    state
}

#[no_mangle]
pub unsafe extern "C" fn chksum_hash_sha1_update(hash: *mut sha1::State<u32>, data: *const u8, length: usize) -> usize {
    if data.is_null() || (length < sha1::BLOCK_LENGTH_BYTES) {
        return 0;
    }
    match hash.as_mut() {
        Some(hash) => {
            for offset in 0..(length / sha1::BLOCK_LENGTH_BYTES) {
                let block = data.add(offset);
                let block = slice::from_raw_parts(block, sha1::BLOCK_LENGTH_BYTES);
                let block = [
                    u32::from_be_bytes([block[0x00], block[0x01], block[0x02], block[0x03]]),
                    u32::from_be_bytes([block[0x04], block[0x05], block[0x06], block[0x07]]),
                    u32::from_be_bytes([block[0x08], block[0x09], block[0x0A], block[0x0B]]),
                    u32::from_be_bytes([block[0x0C], block[0x0D], block[0x0E], block[0x0F]]),
                    u32::from_be_bytes([block[0x10], block[0x11], block[0x12], block[0x13]]),
                    u32::from_be_bytes([block[0x14], block[0x15], block[0x16], block[0x17]]),
                    u32::from_be_bytes([block[0x18], block[0x19], block[0x1A], block[0x1B]]),
                    u32::from_be_bytes([block[0x1C], block[0x1D], block[0x1E], block[0x1F]]),
                    u32::from_be_bytes([block[0x20], block[0x21], block[0x22], block[0x23]]),
                    u32::from_be_bytes([block[0x24], block[0x25], block[0x26], block[0x27]]),
                    u32::from_be_bytes([block[0x28], block[0x29], block[0x2A], block[0x2B]]),
                    u32::from_be_bytes([block[0x2C], block[0x2D], block[0x2E], block[0x2F]]),
                    u32::from_be_bytes([block[0x30], block[0x31], block[0x32], block[0x33]]),
                    u32::from_be_bytes([block[0x34], block[0x35], block[0x36], block[0x37]]),
                    u32::from_be_bytes([block[0x38], block[0x39], block[0x3A], block[0x3B]]),
                    u32::from_be_bytes([block[0x3C], block[0x3D], block[0x3E], block[0x3F]]),
                ];
                hash.update(block);
            }
            length - (length % sha1::BLOCK_LENGTH_BYTES)
        },
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn chksum_hash_sha1_digest(hash: *const sha1::State<u32>) -> *mut u8 {
    match hash.as_ref() {
        Some(hash) => {
            let digest = hash.digest();
            let digest: sha1::Digest<u8> = digest.into();
            let digest: [u8; sha1::DIGEST_LENGTH_BYTES] = digest.into();
            let digest = Box::new(digest);
            Box::into_raw(digest) as *mut u8
        },
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn chksum_hash_sha1_hexdigest(hash: *const sha1::State<u32>) -> *mut c_char {
    match hash.as_ref() {
        Some(hash) => {
            let digest = hash.digest();
            let digest: sha1::Digest<u8> = digest.into();
            let digest = format!("{digest:x}");
            let digest = CString::new(digest).expect("CString::new failed");
            digest.into_raw()
        },
        None => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn chksum_hash_sha1_drop(hash: *mut sha1::State<u32>) {
    drop(Box::from_raw(hash));
}
