use anyhow::{anyhow, ensure, Result};
use serde::{Deserialize, Serialize};

use libsignal_protocol::{IdentityKey, ProtocolAddress};

use super::types::{PublicPreKey, RetrievedDevicePublicKeysResponse, SignedPublicPreKey};
use crate::device::{DeviceAuth, DeviceCreds};
use crate::webapi::WebAPIClient;

#[derive(Serialize, Deserialize)]
pub struct RetrievedDevicePublicKeys {
    #[serde(with = "crate::helpers::serde::identity_key")]
    pub identity_key: IdentityKey,
    pub signed_pre_key: SignedPublicPreKey,
    pub pre_key: Option<PublicPreKey>,
    pub registration_id: u32,
}

impl WebAPIClient {
    pub async fn get_device_keys(
        &self,
        creds: &DeviceCreds,
        remote_address: &ProtocolAddress,
    ) -> Result<RetrievedDevicePublicKeys> {
        let mut response = self
            .http_client
            .get(format!(
                "{}/v2/keys/{}/{}",
                self.server_host,
                remote_address.name(),
                remote_address.device_id()
            ))
            .device_auth(&creds)
            .send()
            .await
            .map_err(|e| anyhow!("retrieving keys: {}", e))?;

        ensure!(
            response.status().is_success(),
            "retrieving device keys: server returned {}",
            response.status()
        );

        let mut response: RetrievedDevicePublicKeysResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("retrieving keys: {}", e))?;

        ensure!(!response.devices.is_empty(), "device not found");
        ensure!(
            response.devices.len() <= 1,
            "server returned multiple devices, whereas only 1 is requested"
        );

        let device = response
            .devices
            .pop()
            .expect("guaranteed by ensure! statement above");
        ensure!(
            device.device_id == remote_address.device_id(),
            "server returned wrong device (device_id mismatched)"
        );

        let signature_valid = response
            .identity_key
            .public_key()
            .verify_signature(
                &device.signed_pre_key.public_key.serialize(),
                &device.signed_pre_key.signature,
            )
            .map_err(|e| anyhow!("cannot verify signature of signed pre key: {}", e))?;
        ensure!(signature_valid, "invalid signature for signed pre key");

        Ok(RetrievedDevicePublicKeys {
            identity_key: response.identity_key,
            signed_pre_key: device.signed_pre_key,
            pre_key: device.pre_key,
            registration_id: device.registration_id,
        })
    }
}
