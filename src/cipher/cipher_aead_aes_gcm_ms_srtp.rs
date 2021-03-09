use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, NewAead, Nonce, Payload},
    Aes128Gcm,
};
use byteorder::{BigEndian, ByteOrder};
use rtp::header;

use super::Cipher;
use crate::{context, error::Error, key_derivation, protection_profile::*};

pub(crate) const CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN: usize = 16;
const RTCP_ENCRYPTION_FLAG: u8 = 0x80;

pub struct MsSrtpSessionKeys {
    srtp_session_crypt_key: Vec<u8>,
    srtp_session_auth_key: Vec<u8>,
    srtp_session_salt_key: Vec<u8>,
    srtcp_session_crypt_key: Vec<u8>,
    srtcp_session_auth_key: Vec<u8>,
    srtcp_session_salt_key: Vec<u8>,
} 

// ToDo: @rainliu whats a use case for srtp_session_auth and srtcp_session_auth
pub struct CipherAeadAesGcmMsSrtp {
    session_keys: MsSrtpSessionKeys,

    srtp_cipher: aes_gcm::Aes128Gcm,
    srtcp_cipher: aes_gcm::Aes128Gcm,
}

impl CipherAeadAesGcmMsSrtp {
    pub fn new(master_key: &[u8], master_salt: &[u8]) -> Result<Self, Error> {
        let srtp_session_key = key_derivation::aes_cm_key_derivation(
            context::LABEL_SRTP_ENCRYPTION,
            master_key,
            master_salt,
            0,
            master_key.len(),
        )?;
        let srtcp_session_key = key_derivation::aes_cm_key_derivation(
            context::LABEL_SRTCP_ENCRYPTION,
            master_key,
            master_salt,
            0,
            master_key.len(),
        )?;

        let srtp_session_salt = key_derivation::aes_cm_key_derivation(
            context::LABEL_SRTP_SALT,
            master_key,
            master_salt,
            0,
            master_salt.len(),
        )?;
        let srtcp_session_salt = key_derivation::aes_cm_key_derivation(
            context::LABEL_SRTCP_SALT,
            master_key,
            master_salt,
            0,
            master_salt.len(),
        )?;

        let auth_key_len = ProtectionProfile::AEADAES128GCM_MS_SRTP.auth_key_len();

        let srtp_session_auth = key_derivation::aes_cm_key_derivation(
            context::LABEL_SRTP_AUTHENTICATION_TAG,
            master_key,
            master_salt,
            0,
            auth_key_len,
        )?;
        let srtcp_session_auth = key_derivation::aes_cm_key_derivation(
            context::LABEL_SRTCP_AUTHENTICATION_TAG,
            master_key,
            master_salt,
            0,
            auth_key_len,
        )?;

        let srtp_block = GenericArray::from_slice(&srtp_session_key);
        let srtp_cipher = Aes128Gcm::new(srtp_block);

        let srtcp_block = GenericArray::from_slice(&srtcp_session_key);
        let srtcp_cipher = Aes128Gcm::new(srtcp_block);

        let session_keys = MsSrtpSessionKeys {
            srtp_session_crypt_key: srtp_session_key.to_vec(),
            srtp_session_auth_key: srtp_session_auth.to_vec(),
            srtp_session_salt_key: srtp_session_salt.to_vec(),

            srtcp_session_crypt_key: srtcp_session_key.to_vec(),
            srtcp_session_auth_key: srtcp_session_auth.to_vec(),
            srtcp_session_salt_key: srtcp_session_salt.to_vec(),
        };

        Ok(CipherAeadAesGcmMsSrtp {
            session_keys: session_keys,
            srtp_cipher: srtp_cipher,
            srtcp_cipher: srtcp_cipher,
        })
    }

    /// Generate IV according to https://tools.ietf.org/html/rfc3711#section-4.1.1
    pub(crate) fn rtp_initialization_vector(
        &self,
        header: &rtp::header::Header,
        roc: u32,
        session_salt_key: &[u8]
    ) -> Result<Vec<u8>, Error> {
        key_derivation::generate_counter(
            header.sequence_number, roc, header.ssrc, session_salt_key
        )
    }

    /// The 12-octet IV used by AES-GCM SRTCP is formed by first
    /// concatenating 2 octets of zeroes, the 4-octet SSRC identifier,
    /// 2 octets of zeroes, a single "0" bit, and the 31-bit SRTCP index.
    /// The resulting 12-octet value is then XORed to the 12-octet salt to
    /// form the 12-octet IV.
    ///
    /// https://tools.ietf.org/html/rfc7714#section-9.1
    pub(crate) fn rtcp_initialization_vector(
        &self,
        srtcp_index: usize,
        ssrc: u32,
        session_salt_key: &[u8]
    ) -> Vec<u8> {
        let mut iv = vec![0u8; 12];

        BigEndian::write_u32(&mut iv[2..], ssrc);
        BigEndian::write_u32(&mut iv[8..], srtcp_index as u32);

        for (i, v) in iv.iter_mut().enumerate() {
            *v ^= session_salt_key[i];
        }

        iv
    }

    /// In an SRTCP packet, a 1-bit Encryption flag is prepended to the
    /// 31-bit SRTCP index to form a 32-bit value we shall call the
    /// "ESRTCP word"
    ///
    /// https://tools.ietf.org/html/rfc7714#section-17
    pub(crate) fn rtcp_additional_authenticated_data(
        &self,
        rtcp_packet: &[u8],
        srtcp_index: usize,
    ) -> Vec<u8> {
        let mut aad = vec![0u8; 12];

        aad[..8].copy_from_slice(&rtcp_packet[..8]);

        BigEndian::write_u32(&mut aad[8..], srtcp_index as u32);

        aad[8] |= RTCP_ENCRYPTION_FLAG;
        aad
    }
}

impl Cipher for CipherAeadAesGcmMsSrtp {
    fn auth_tag_len(&self) -> usize {
        CIPHER_AEAD_AES_GCM_AUTH_TAG_LEN
    }

    fn get_rtcp_index(&self, input: &[u8]) -> usize {
        let pos = input.len() - 4;
        let val = BigEndian::read_u32(&input[pos..]);

        (val & !((RTCP_ENCRYPTION_FLAG as u32) << 24)) as usize
    }

    fn encrypt_rtp(
        &mut self,
        payload: &[u8],
        header: &rtp::header::Header,
        roc: u32,
    ) -> Result<Vec<u8>, Error> {
        let mut writer: Vec<u8> = Vec::new();

        header.marshal(&mut writer)?;
        let nonce = self.rtp_initialization_vector(header, roc, &self.session_keys.srtp_session_salt_key)?;

        let mut encrypted = self.srtp_cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload,
                aad: &writer,
            },
        )?;

        writer.append(&mut encrypted);
        Ok(writer)
    }

    fn decrypt_rtp(
        &mut self,
        ciphertext: &[u8],
        header: &rtp::header::Header,
        roc: u32,
    ) -> Result<Vec<u8>, Error> {
        let nonce = self.rtp_initialization_vector(header, roc, &self.session_keys.srtp_session_salt_key)?;

        let decrypted_msg: Vec<u8> = self.srtp_cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext[header.payload_offset..],
                aad: &ciphertext[..header.payload_offset],
            },
        )?;

        let mut decrypted_msg = [vec![0; header.payload_offset], decrypted_msg].concat();

        decrypted_msg[..header.payload_offset]
            .copy_from_slice(&ciphertext[..header.payload_offset]);

        Ok(decrypted_msg)
    }

    fn encrypt_rtcp(
        &mut self,
        decrypted: &[u8],
        srtcp_index: usize,
        ssrc: u32,
    ) -> Result<Vec<u8>, Error> {
        let iv = self.rtcp_initialization_vector(srtcp_index, ssrc, &self.session_keys.srtp_session_salt_key);

        let aad = self.rtcp_additional_authenticated_data(decrypted, srtcp_index);

        let encrypted_data = self.srtcp_cipher.encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &decrypted[8..],
                aad: &aad,
            },
        )?;

        let mut encrypted_data = [vec![0; 8], encrypted_data].concat();

        encrypted_data[..8].copy_from_slice(&decrypted[..8]);
        encrypted_data.append(&mut aad[8..].to_vec());

        Ok(encrypted_data)
    }

    fn decrypt_rtcp(
        &mut self,
        encrypted: &[u8],
        srtcp_index: usize,
        ssrc: u32,
    ) -> Result<Vec<u8>, Error> {
        let nonce = self.rtcp_initialization_vector(srtcp_index, ssrc, &self.session_keys.srtp_session_salt_key);

        let aad = self.rtcp_additional_authenticated_data(&encrypted, srtcp_index);

        let decrypted_data = self.srtcp_cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &encrypted[8..(encrypted.len() - context::SRTCP_INDEX_SIZE)],
                aad: &aad,
            },
        )?;

        let decrypted_data = [encrypted[..8].to_vec(), decrypted_data].concat();
        Ok(decrypted_data)
    }
}
