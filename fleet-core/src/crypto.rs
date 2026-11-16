//! Event authority, node keys, card / frame / revocation verification.
//! No RNG here: every seed comes from the caller.

use crate::consts::*;
use crate::kit::{KitError, Tables};
use crate::wire::{Body, Card, Header, Role, WireError, decode, encode_unsigned, signed_region};
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Organiser-only: holds the event signing key.
pub struct EventAuthority {
    pub(crate) seed: [u8; 32],
    pub(crate) event_id: [u8; 8],
    pub(crate) start: u32,
    pub(crate) expiry: u32,
}

impl EventAuthority {
    pub fn new(seed: [u8; 32], event_id: [u8; 8], start: u32, expiry: u32) -> Self {
        EventAuthority {
            seed,
            event_id,
            start,
            expiry,
        }
    }
    pub fn public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }

    /// Card expiry is clamped to the event's expiry.
    pub fn issue_card(&self, pubkey: [u8; 32], node: u16, role: Role, expiry: u32) -> Card {
        let expiry = expiry.min(self.expiry);
        let msg = card_msg(&self.event_id, &pubkey, node, role, expiry);
        let event_sig = SigningKey::from_bytes(&self.seed).sign(&msg).to_bytes();
        Card {
            pubkey,
            node,
            role,
            expiry,
            event_sig,
        }
    }

    pub fn revocation_sig(&self, target: u16) -> [u8; 64] {
        let msg = revoke_msg(&self.event_id, target);
        SigningKey::from_bytes(&self.seed).sign(&msg).to_bytes()
    }

    pub(crate) fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        SigningKey::from_bytes(&self.seed).sign(msg).to_bytes()
    }
    #[allow(clippy::too_many_arguments)]
    pub fn make_kit(
        &self,
        device_seed: [u8; 32],
        node: u16,
        role: Role,
        tables: Tables,
        tag_secret: [u8; 32],
        checkin_minutes: u8,
        channel: Vec<u8>,
    ) -> Result<Vec<u8>, KitError> {
        if node == 0 {
            return Err(KitError::Malformed);
        }
        let card = self.issue_card(
            SigningKey::from_bytes(&device_seed)
                .verifying_key()
                .to_bytes(),
            node,
            role,
            self.expiry,
        );
        self.build_kit(
            device_seed,
            card,
            tables,
            tag_secret,
            checkin_minutes,
            channel,
        )
    }
}

pub struct NodeKey {
    seed: [u8; 32],
}

impl NodeKey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        NodeKey { seed }
    }
    pub fn public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }

    pub fn sign_frame(
        &self,
        event_id: &[u8; 8],
        h: &Header,
        b: &Body,
    ) -> Result<Vec<u8>, WireError> {
        let mut frame = encode_unsigned(h, b)?;
        let sig = SigningKey::from_bytes(&self.seed).sign(&frame_msg(event_id, &frame));
        frame.extend_from_slice(&sig.to_bytes());
        Ok(frame)
    }
}

fn card_msg(event_id: &[u8; 8], pubkey: &[u8; 32], node: u16, role: Role, expiry: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOM_CARD.len() + 8 + 32 + 2 + 1 + 4);
    m.extend_from_slice(DOM_CARD);
    m.extend_from_slice(event_id);
    m.extend_from_slice(pubkey);
    m.extend_from_slice(&node.to_be_bytes());
    m.push(role.code());
    m.extend_from_slice(&expiry.to_be_bytes());
    m
}

fn frame_msg(event_id: &[u8; 8], unsigned: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOM_FRAME.len() + 8 + unsigned.len());
    m.extend_from_slice(DOM_FRAME);
    m.extend_from_slice(event_id);
    m.extend_from_slice(unsigned);
    m
}

fn revoke_msg(event_id: &[u8; 8], target: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOM_REVOKE.len() + 8 + 2);
    m.extend_from_slice(DOM_REVOKE);
    m.extend_from_slice(event_id);
    m.extend_from_slice(&target.to_be_bytes());
    m
}

/// Strict verification; an invalid public key is simply `false`.
pub(crate) fn verify_raw(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk.verify_strict(msg, &Signature::from_bytes(sig)).is_ok(),
        Err(_) => false,
    }
}

pub fn verify_card(event_pub: &[u8; 32], event_id: &[u8; 8], c: &Card) -> bool {
    let msg = card_msg(event_id, &c.pubkey, c.node, c.role, c.expiry);
    verify_raw(event_pub, &msg, &c.event_sig)
}

/// Decodes first, so only well-formed frames can verify.
pub fn verify_frame(pubkey: &[u8; 32], event_id: &[u8; 8], bytes: &[u8]) -> bool {
    let frame = match decode(bytes) {
        Ok(f) => f,
        Err(_) => return false,
    };
    verify_raw(
        pubkey,
        &frame_msg(event_id, signed_region(bytes)),
        &frame.sig,
    )
}

pub fn verify_revocation(
    event_pub: &[u8; 32],
    event_id: &[u8; 8],
    target: u16,
    sig: &[u8; 64],
) -> bool {
    verify_raw(event_pub, &revoke_msg(event_id, target), sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Level, VerdictKind};

    const EID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    fn auth() -> EventAuthority {
        EventAuthority::new([9; 32], EID, 1_000, 100_000)
    }

    #[test]
    fn card_verifies_and_rejects_tamper() {
        let a = auth();
        let nk = NodeKey::from_seed([5; 32]);
        let c = a.issue_card(nk.public(), 7, Role::Full, 50_000);
        assert!(verify_card(&a.public(), &EID, &c));
        let mut t = c.clone();
        t.node = 8;
        assert!(!verify_card(&a.public(), &EID, &t));
        let mut t = c.clone();
        t.role = Role::Light;
        assert!(!verify_card(&a.public(), &EID, &t));
        let mut t = c.clone();
        t.expiry += 1;
        assert!(!verify_card(&a.public(), &EID, &t));
        let other = EventAuthority::new([10; 32], EID, 1_000, 100_000);
        assert!(!verify_card(&other.public(), &EID, &c));
        assert!(!verify_card(&a.public(), &[0; 8], &c));
        // garbage public key must not panic
        assert!(!verify_card(&[0xFF; 32], &EID, &c));
    }

    #[test]
    fn card_expiry_clamped() {
        let a = auth();
        let c = a.issue_card([1; 32], 3, Role::Light, 100_000 + 999);
        assert_eq!(c.expiry, 100_000);
        let c = a.issue_card([1; 32], 3, Role::Light, 5);
        assert_eq!(c.expiry, 5);
    }

    #[test]
    fn frame_sign_verify() {
        let nk = NodeKey::from_seed([5; 32]);
        let h = Header {
            node: 7,
            counter: 99,
            time: 5_000,
        };
        let b = Body::Verdict {
            kind: VerdictKind::ImsiRequested,
            level: Level::High,
            tag: None,
        };
        let f = nk.sign_frame(&EID, &h, &b).unwrap();
        assert!(verify_frame(&nk.public(), &EID, &f));
        let other = NodeKey::from_seed([6; 32]);
        assert!(!verify_frame(&other.public(), &EID, &f));
        assert!(!verify_frame(&nk.public(), &[0; 8], &f));
        assert!(!verify_frame(&[0xFF; 32], &EID, &f));
        for i in 0..f.len() {
            for bit in 0..8 {
                let mut g = f.clone();
                g[i] ^= 1 << bit;
                assert!(!verify_frame(&nk.public(), &EID, &g), "byte {i} bit {bit}");
            }
        }
        assert!(!verify_frame(&nk.public(), &EID, &f[..f.len() - 1]));
    }

    #[test]
    fn revocation_sig_verifies() {
        let a = auth();
        let s = a.revocation_sig(12);
        assert!(verify_revocation(&a.public(), &EID, 12, &s));
        assert!(!verify_revocation(&a.public(), &EID, 13, &s));
        assert!(!verify_revocation(&a.public(), &[0; 8], 12, &s));
    }
}
