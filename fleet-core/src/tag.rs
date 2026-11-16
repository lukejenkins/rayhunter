//! Tower tags: the only tower data that ever leaves a node.

use crate::consts::*;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn tower_tag(secret: &[u8; 32], plmn: &str, tac: u16, eci: u32) -> [u8; TAG_LEN] {
    let p = plmn.as_bytes();
    let p = &p[..p.len().min(255)];
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC takes any key length");
    let mut m: Vec<u8> = Vec::with_capacity(DOM_TAG.len() + 1 + p.len() + 6);
    m.extend_from_slice(DOM_TAG);
    m.push(p.len() as u8);
    m.extend_from_slice(p);
    m.extend_from_slice(&tac.to_be_bytes());
    m.extend_from_slice(&eci.to_be_bytes());
    mac.update(&m);
    let out = mac.finalize().into_bytes();
    let mut t = [0u8; TAG_LEN];
    t.copy_from_slice(&out[..TAG_LEN]);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_properties() {
        let s = [7u8; 32];
        let t = tower_tag(&s, "310260", 0x1234, 0x0abc_def1);
        assert_eq!(t, tower_tag(&s, "310260", 0x1234, 0x0abc_def1));
        assert_ne!(t, tower_tag(&[8u8; 32], "310260", 0x1234, 0x0abc_def1));
        assert_ne!(t, tower_tag(&s, "310260", 0x1235, 0x0abc_def1));
        assert_ne!(t, tower_tag(&s, "310260", 0x1234, 0x0abc_def2));
        assert_ne!(t, tower_tag(&s, "310261", 0x1234, 0x0abc_def1));
        // length prefix: "310260"+tac/eci vs "31026"+shifted bytes can't collide
        // "310260" tac=0x1234 -> "...0" then 0x12 0x34; "31026" tac=0x3012 eci shifted
        let a = tower_tag(&s, "310260", 0x1234, 0x5678_9abc);
        let b = tower_tag(&s, "31026", 0x3012, 0x3456_789a);
        assert_ne!(a, b);
    }
}
