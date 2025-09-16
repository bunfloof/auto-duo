use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use reqwest::{
    Client as HttpClient,
    header::{HeaderMap, HeaderValue},
};
use rsa::signature::SignatureEncoding;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding},
};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha512;
use tokio::time::sleep;

#[derive(Debug, Clone)]
struct Client {
    pubkey: RsaPrivateKey,
    pkey: Option<String>,
    akey: Option<String>,
    host: Option<String>,
    code: Option<String>,
    info: HashMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct TransactionResponse {
    stat: String,
    response: Option<TransactionsData>,
}

#[derive(Debug, Deserialize)]
struct TransactionsData {
    transactions: Vec<Transaction>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Transaction {
    urgid: String,
    #[serde(flatten)]
    other: HashMap<String, Value>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ActivationResponse {
    #[serde(default)]
    response: Option<ActivationData>,
    #[serde(flatten)]
    data: HashMap<String, Value>,
}

#[derive(Deserialize, Clone)]
#[allow(dead_code)]
struct ActivationData {
    akey: String,
    pkey: String,
    #[serde(default)]
    host: Option<String>,
    #[serde(flatten)]
    other: HashMap<String, Value>,
}

impl Client {
    fn new() -> Self {
        use rand_core::OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut OsRng, bits).expect("failed to generate key");

        Client {
            pubkey: private_key,
            pkey: None,
            akey: None,
            host: None,
            code: None,
            info: HashMap::new(),
        }
    }

    fn import_key(
        &mut self, keyfile: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key_data = fs::read_to_string(keyfile)?;
        self.pubkey = RsaPrivateKey::from_pkcs8_pem(&key_data)?;
        Ok(())
    }

    fn export_key(&self, file: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pem = self.pubkey.to_pkcs8_pem(LineEnding::LF)?;
        fs::write(file, pem.as_bytes())?;
        Ok(())
    }

    fn read_code(&mut self, code: &str) {
        let parts: Vec<&str> = code.split('-').collect();
        if parts.len() != 2 {
            panic!("Invalid code format");
        }

        let code_part = parts[0].trim_matches(|c| c == '<' || c == '>');
        let mut host_part = parts[1].trim_matches(|c| c == '<' || c == '>').to_string();

        let missing_padding = host_part.len() % 4;
        if missing_padding != 0 {
            host_part.push_str(&"=".repeat(4 - missing_padding));
        }

        let host_bytes = general_purpose::STANDARD.decode(&host_part).expect("Invalid base64");
        let host = String::from_utf8(host_bytes).expect("Invalid UTF-8");

        self.code = Some(code_part.to_string());
        self.host = Some(host);
    }

    fn import_response(
        &mut self, response_path: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let data = fs::read_to_string(response_path)?;
        let mut response: HashMap<String, Value> = serde_json::from_str(&data)?;

        if let Some(resp) = response.get("response") {
            if let Some(obj) = resp.as_object() {
                response = obj.clone().into_iter().collect();
            }
        }

        self.info = response.clone();

        if let Some(host) = &self.host {
            if !self.info.contains_key("host") || self.info["host"].is_null() {
                self.info.insert("host".to_string(), Value::String(host.clone()));
            }
        } else if let Some(Value::String(host)) = self.info.get("host") {
            self.host = Some(host.clone());
        }

        if let Some(Value::String(akey)) = response.get("akey") {
            self.akey = Some(akey.clone());
        }
        if let Some(Value::String(pkey)) = response.get("pkey") {
            self.pkey = Some(pkey.clone());
        }

        Ok(())
    }

    fn export_response(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if let Some(host) = &self.host {
            if !self.info.contains_key("host") || self.info["host"].is_null() {
                self.info.insert("host".to_string(), Value::String(host.clone()));
            }
        }

        let json = serde_json::to_string_pretty(&self.info)?;
        fs::write("response.json", json)?;
        Ok(())
    }

    async fn activate(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.code.is_none() {
            return Err("Code is null".into());
        }

        let public_key = RsaPublicKey::from(&self.pubkey);
        let pubkey_pem = public_key.to_public_key_pem(LineEnding::LF)?;

        let mut params = HashMap::new();
        params.insert("jailbroken", "false");
        params.insert("architecture", "arch64");
        params.insert("region", "US");
        params.insert("app_id", "com.duosecurity.duomobile");
        params.insert("full_disk_encryption", "true");
        params.insert("passcode_status", "true");
        params.insert("platform", "Android");
        params.insert("app_version", "4.97.0");
        params.insert("app_build_number", "4097001");
        params.insert("version", "13");
        params.insert("manufacturer", "unknown");
        params.insert("language", "en");
        params.insert("model", "Extension");
        params.insert("security_patch_level", "2025-09-10");
        params.insert("pkpush", "rsa-sha512");
        params.insert("pubkey", &pubkey_pem);

        let client = HttpClient::new();
        let url = format!(
            "https://{}/push/v2/activation/{}",
            self.host.as_ref().unwrap(),
            self.code.as_ref().unwrap()
        );

        let response = client.post(&url).query(&params).send().await?;

        let response_text = response.text().await?;
        let activation_response: HashMap<String, Value> = serde_json::from_str(&response_text)?;

        if let Some(resp_obj) = activation_response.get("response") {
            if let Some(obj) = resp_obj.as_object() {
                self.info = obj.clone().into_iter().collect();
            }
        } else {
            self.info = activation_response;
        }

        if let Some(Value::String(akey)) = self.info.get("akey") {
            self.akey = Some(akey.clone());
        }
        if let Some(Value::String(pkey)) = self.info.get("pkey") {
            self.pkey = Some(pkey.clone());
        }

        Ok(())
    }

    fn generate_signature(
        &self, method: &str, path: &str, time: &str, data: &HashMap<&str, &str>,
    ) -> String {
        let host = self.host.as_ref().expect("Host is required");
        let pkey = self.pkey.as_ref().expect("Pkey is required");

        let mut query_parts: Vec<String> = data
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect();
        query_parts.sort();
        let query_string = query_parts.join("&");

        let message =
            format!("{}\n{}\n{}\n{}\n{}", time, method, host.to_lowercase(), path, query_string);

        println!("{}", message);

        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::Signer;

        let signing_key = SigningKey::<Sha512>::new(self.pubkey.clone());
        let signature = signing_key.sign(message.as_bytes());

        let signature_b64 = general_purpose::STANDARD.encode(signature.to_bytes());
        let sig_pair_b64 = format!("{}:{}", pkey, signature_b64);
        let auth = format!("Basic {}", general_purpose::STANDARD.encode(sig_pair_b64));

        auth
    }

    async fn get_transactions(
        &self,
    ) -> Result<TransactionResponse, Box<dyn std::error::Error + Send + Sync>> {
        let dt = Utc::now();
        let time = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let path = "/push/v2/device/transactions";

        let mut data = HashMap::new();
        data.insert("akey", self.akey.as_ref().unwrap().as_str());
        data.insert("fips_status", "1");
        data.insert("hsm_status", "true");
        data.insert("pkpush", "rsa-sha512");

        let signature = self.generate_signature("GET", path, &time, &data);

        let mut headers = HeaderMap::new();
        headers.insert("Authorization", HeaderValue::from_str(&signature)?);
        headers.insert("x-duo-date", HeaderValue::from_str(&time)?);
        headers.insert("host", HeaderValue::from_str(self.host.as_ref().unwrap())?);

        let client = HttpClient::new();
        let url = format!("https://{}{}", self.host.as_ref().unwrap(), path);

        let response = client.get(&url).headers(headers).query(&data).send().await?;

        let response_text = response.text().await?;
        let transaction_response: TransactionResponse = serde_json::from_str(&response_text)?;

        Ok(transaction_response)
    }

    async fn reply_transaction(
        &self, transactionid: &str, answer: &str,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let dt = Utc::now();
        let time = dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let path = format!("/push/v2/device/transactions/{}", transactionid);

        let mut data = HashMap::new();
        data.insert("akey", self.akey.as_ref().unwrap().as_str());
        data.insert("answer", answer);
        data.insert("fips_status", "1");
        data.insert("hsm_status", "true");
        data.insert("pkpush", "rsa-sha512");

        let signature = self.generate_signature("POST", &path, &time, &data);

        let mut headers = HeaderMap::new();
        headers.insert("Authorization", HeaderValue::from_str(&signature)?);
        headers.insert("x-duo-date", HeaderValue::from_str(&time)?);
        headers.insert("host", HeaderValue::from_str(self.host.as_ref().unwrap())?);
        headers.insert("txId", HeaderValue::from_str(transactionid)?);

        let client = HttpClient::new();
        let url = format!("https://{}{}", self.host.as_ref().unwrap(), &path);

        let response = client.post(&url).headers(headers).form(&data).send().await?;

        let response_text = response.text().await?;
        let json_response: Value = serde_json::from_str(&response_text)?;

        Ok(json_response)
    }
}

async fn loop_each(client: Arc<Client>) {
    match client.get_transactions().await {
        Ok(r) => {
            if r.stat == "FAIL" {
                println!("{:?}", r);
                return;
            }

            if let Some(response) = r.response {
                let transactions = response.transactions;
                println!("Checking for transactions");

                if !transactions.is_empty() {
                    for tx in transactions {
                        println!("{:?}", tx);
                        if let Err(e) = client.reply_transaction(&tx.urgid, "approve").await {
                            println!("Error replying to transaction: {}", e);
                        }
                        sleep(Duration::from_secs(2)).await;
                    }
                } else {
                    println!("No transactions");
                }
            }
        }
        Err(e) => {
            println!("Connection Error: {}", e);
            sleep(Duration::from_secs(5)).await;
            return;
        }
    }

    sleep(Duration::from_secs(1)).await;
}

async fn polling_loop(client: Arc<Client>) {
    loop {
        loop_each(client.clone()).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = Client::new();
    let mut key_exists = false;

    if Path::new("key.pem").exists() {
        client.import_key("key.pem")?;
        key_exists = true;
    } else {
        client.export_key("key.pem")?;
    }

    if Path::new("response.json").exists() && key_exists {
        client.import_response("response.json")?;

        if client.host.is_none() {
            print!("Input code: ");
            io::stdout().flush()?;
            let mut code = String::new();
            io::stdin().read_line(&mut code)?;
            client.read_code(&code.trim());
            client.export_response()?;
        }
    } else {
        print!("Input code: ");
        io::stdout().flush()?;
        let mut code = String::new();
        io::stdin().read_line(&mut code)?;
        client.read_code(&code.trim());
        client.activate().await?;
        client.export_response()?;
    }

    let client_arc = Arc::new(client);
    let poll_handle = tokio::spawn(polling_loop(client_arc));

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    poll_handle.abort();

    Ok(())
}
