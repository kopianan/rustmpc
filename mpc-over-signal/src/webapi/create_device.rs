use awc::http::StatusCode;

use anyhow::{anyhow, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use rand::{CryptoRng, Rng};

use super::link_device::DecryptedProvision;
use super::WebAPIClient;
use crate::device::{DeviceCreds, Username};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateDeviceRequest {
    pub name: String,
    pub fetches_messages: bool,
    pub registration_id: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateDeviceResponse {
    pub device_id: u32,
}

impl WebAPIClient {
    pub async fn create_device<R: Rng + CryptoRng>(
        &self,
        rnd: &mut R,
        provision: &DecryptedProvision,
        device_name: String,
    ) -> Result<DeviceCreds> {
        let mut password = [0u8; 16];
        rnd.fill_bytes(&mut password);
        let mut password_64 = base64::encode(password);
        password_64.drain(password_64.len() - 2..);

        let registration_id = rnd.gen::<u32>() & 0x3fff;

        let request_body = CreateDeviceRequest {
            name: device_name,
            fetches_messages: true,
            registration_id,
        };

        let mut response = self
            .http_client
            .put(format!(
                "{}/v1/devices/{}",
                self.server_host, provision.provisioning_code
            ))
            .basic_auth(&provision.number, Some(&password_64))
            .send_json(&request_body)
            .await
            .map_err(|e| anyhow!("creating new device: {}", e))?;

        ensure!(
            response.status() == StatusCode::OK,
            "creating new device: server returned {}",
            response.status()
        );

        let created_device: CreateDeviceResponse =
            response.json().await.context("parse server response")?;

        Ok(DeviceCreds::new(
            Username {
                name: provision.uuid.clone(),
                device_id: created_device.device_id,
            },
            password_64,
            registration_id,
        ))
    }
}
