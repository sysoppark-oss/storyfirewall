//! 파일 SHA-256 (A20). 출신 기록 시점에 서명 없음·인터넷에서 받은 실행 파일의 해시를 남겨,
//! 나중에 끊기·격리할 때 "그 파일이 그때 그 파일인가"를 확인한다.

use std::io::Read;

use sha2::{Digest, Sha256};

/// 이보다 큰 파일은 해시하지 않는다 (수집 스레드를 오래 잡지 않게)
pub const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashOutcome {
    Ok { sha256: String, size: u64 },
    TooLarge { size: u64 },
    Unreadable(String),
}

pub fn sha256_file(path: &str) -> HashOutcome {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return HashOutcome::Unreadable(e.to_string()),
    };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    if size > MAX_HASH_BYTES {
        return HashOutcome::TooLarge { size };
    }
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                h.update(&buf[..n]);
                total += n as u64;
                if total > MAX_HASH_BYTES {
                    return HashOutcome::TooLarge { size: total };
                }
            }
            Err(e) => return HashOutcome::Unreadable(e.to_string()),
        }
    }
    HashOutcome::Ok {
        sha256: hex(&h.finalize()),
        size: total,
    }
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_vector_and_missing_file() {
        let p = std::env::temp_dir().join(format!("sf-hash-{}", std::process::id()));
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(
            sha256_file(p.to_str().unwrap()),
            HashOutcome::Ok {
                sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
                size: 3
            }
        );
        std::fs::remove_file(&p).unwrap();
        assert!(matches!(
            sha256_file(p.to_str().unwrap()),
            HashOutcome::Unreadable(_)
        ));
    }
}
