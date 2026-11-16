//! Tower and identity extraction shared by the daemon and the add-on's wasm
//! decoder, so both identify towers identically.

use pycrate_rs::nas::NASMessage;
use pycrate_rs::nas::emm::EMMMessage;
use telcom_parser::lte_rrc::{BCCH_DL_SCH_MessageType, BCCH_DL_SCH_MessageType_c1, MCC_MNC_Digit};

use crate::analysis::information_element::{InformationElement, LteInformationElement};
use crate::diag::Message;
use crate::diag::diaglog::LogBody;
use crate::diag::diaglog::rrc::LteRrcOtaPacket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sib1Tower {
    pub plmn: Option<String>,
    pub tac: u64,
    pub cell: u64,
}

fn digits(d: &[MCC_MNC_Digit]) -> String {
    d.iter().map(|MCC_MNC_Digit(n)| n.to_string()).collect()
}

/// Big-endian fold of an ASN.1 bit string (TAC 16 bits, cell ID 28 bits).
fn fold_bits<'a>(bits: impl Iterator<Item = bool> + 'a) -> u64 {
    bits.fold(0u64, |acc, b| (acc << 1) | b as u64)
}

pub fn sib1_tower(element: &InformationElement) -> Option<Sib1Tower> {
    let InformationElement::LTE(lte) = element else {
        return None;
    };
    let LteInformationElement::BcchDlSch(msg) = &**lte else {
        return None;
    };
    let BCCH_DL_SCH_MessageType::C1(BCCH_DL_SCH_MessageType_c1::SystemInformationBlockType1(sib1)) =
        &msg.message
    else {
        return None;
    };
    let access = &sib1.cell_access_related_info;
    // The first PLMN is the primary one; an absent MCC in the first entry
    // has nothing to inherit from.
    let plmn = access.plmn_identity_list.0.first().map(|info| {
        let id = &info.plmn_identity;
        let mcc = id.mcc.as_ref().map(|m| digits(&m.0)).unwrap_or_default();
        format!("{}-{}", mcc, digits(&id.mnc.0))
    });
    Some(Sib1Tower {
        plmn,
        tac: fold_bits(access.tracking_area_code.0.iter().map(|b| *b)),
        cell: fold_bits(access.cell_identity.0.iter().map(|b| *b)),
    })
}

pub fn is_identity_request(element: &InformationElement) -> bool {
    matches!(
        element,
        InformationElement::LTE(lte) if matches!(
            &**lte,
            LteInformationElement::NAS(NASMessage::EMMMessage(EMMMessage::EMMIdentityRequest(_)))
        )
    )
}

pub fn rrc_cell(msg: &Message) -> Option<(u16, u32)> {
    let Message::Log {
        body: LogBody::LteRrcOtaMessage { packet, .. },
        ..
    } = msg
    else {
        return None;
    };
    let pci = match packet {
        LteRrcOtaPacket::V0 { phy_cell_id, .. }
        | LteRrcOtaPacket::V5 { phy_cell_id, .. }
        | LteRrcOtaPacket::V8 { phy_cell_id, .. }
        | LteRrcOtaPacket::V25 { phy_cell_id, .. } => *phy_cell_id,
    };
    Some((pci, packet.get_earfcn()))
}
