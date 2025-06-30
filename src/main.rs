use axum::{
    body::Bytes,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use base64;
use bs58;
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer, Signature},
};
use spl_token::instruction::{initialize_mint, mint_to};
use std::{net::SocketAddr, str::FromStr};
use std::{convert::TryFrom};
use solana_sdk::system_instruction;
use spl_token::instruction::transfer;


#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

enum ApiResponse<T> {
    Success(T),
    Error(String),
}

impl<T> IntoResponse for ApiResponse<T>
where
    T: Serialize,
{
    fn into_response(self) -> axum::response::Response {
        match self {
            ApiResponse::Success(data) => {
                let body = serde_json::to_string(&SuccessResponse {
                    success: true,
                    data,
                })
                .unwrap();

                (StatusCode::OK, [("Content-Type", "application/json")], body).into_response()
            }
            ApiResponse::Error(error_msg) => {
                let body = serde_json::to_string(&ErrorResponse {
                    success: false,
                    error: error_msg,
                })
                .unwrap();

                (StatusCode::BAD_REQUEST, [("Content-Type", "application/json")], body).into_response()
            }
        }
    }
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

async fn keypair_handler() -> ApiResponse<KeypairData> {
    let keypair = Keypair::new();
    println!("Keypair debug: {:?}", keypair);

    let pubkey_str = keypair.pubkey().to_string();

    let secret_key_bytes = keypair.to_bytes();
    let secret_key = bs58::encode(secret_key_bytes).into_string();

    let data = KeypairData {
        pubkey: pubkey_str,
        secret: secret_key,
    };

    ApiResponse::Success(data)
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct CreateTokenResponseData {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

async fn create_token_handler(raw_body: Bytes) -> impl IntoResponse {
    let payload: CreateTokenRequest = match serde_json::from_slice(&raw_body) {
        Ok(p) => p,
        Err(e) => {
            return ApiResponse::Error(format!("Invalid JSON or missing required fields: {}", e));
        }
    };

    let mint_authority = match Pubkey::from_str(&payload.mintAuthority) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid mintAuthority pubkey".to_string()),
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid mint pubkey".to_string()),
    };

    let instruction: Instruction = match initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        None,
        payload.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => return ApiResponse::Error(format!("Failed to create instruction: {}", e)),
    };

    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| AccountMetaResponse {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect::<Vec<_>>();

    let instruction_data = base64::encode(&instruction.data);

    let response_data = CreateTokenResponseData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };

    ApiResponse::Success(response_data)
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct MintTokenResponseData {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

async fn mint_token_handler(raw_body: Bytes) -> impl IntoResponse {
    let payload: MintTokenRequest = match serde_json::from_slice(&raw_body) {
        Ok(p) => p,
        Err(e) => {
            return ApiResponse::Error(format!("Invalid JSON or missing required fields: {}", e));
        }
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid mint pubkey".to_string()),
    };

    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid destination pubkey".to_string()),
    };

    let authority = match Pubkey::from_str(&payload.authority) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid authority pubkey".to_string()),
    };

    let instruction: Instruction = match mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return ApiResponse::Error(format!("Failed to create mint_to instruction: {}", e)),
    };

    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| AccountMetaResponse {
            pubkey: meta.pubkey.to_string(),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect::<Vec<_>>();

    let instruction_data = base64::encode(&instruction.data);

    let response_data = MintTokenResponseData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };

    ApiResponse::Success(response_data)
}


#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponseData {
    signature: String,
    public_key: String,
    message: String,
}


async fn sign_message_handler(raw_body: Bytes) -> impl IntoResponse {
    // Deserialize JSON and handle errors
    let payload: SignMessageRequest = match serde_json::from_slice(&raw_body) {
        Ok(p) => p,
        Err(_) => {
            return ApiResponse::Error("Missing required fields".to_string());
        }
    };

    // Check that required fields are not empty
    if payload.message.trim().is_empty() || payload.secret.trim().is_empty() {
        return ApiResponse::Error("Missing required fields".to_string());
    }

    // Decode secret key from base58
    let secret_bytes = match bs58::decode(&payload.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return ApiResponse::Error("Invalid base58 secret key".to_string()),
    };

    // Reconstruct keypair from bytes
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => return ApiResponse::Error("Invalid secret key bytes".to_string()),
    };

    // Sign the message bytes
    let message_bytes = payload.message.as_bytes();
    let signature: Signature = keypair.sign_message(message_bytes);

    // Encode signature as base64
    let signature_base64 = base64::encode(signature.as_ref());

    let response_data = SignMessageResponseData {
        signature: signature_base64,
        public_key: keypair.pubkey().to_string(),
        message: payload.message,
    };

    ApiResponse::Success(response_data)
}


#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponseData {
    valid: bool,
    message: String,
    pubkey: String,
}
async fn verify_message_handler(raw_body: Bytes) -> impl IntoResponse {
    let payload: VerifyMessageRequest = match serde_json::from_slice(&raw_body) {
        Ok(p) => p,
        Err(e) => {
            return ApiResponse::Error(format!("Missing required fields or invalid JSON: {}", e));
        }
    };

    let signature_bytes_vec = match base64::decode(&payload.signature) {
        Ok(bytes) => bytes,
        Err(_) => return ApiResponse::Error("Invalid base64 signature".to_string()),
    };

    if signature_bytes_vec.len() != 64 {
        return ApiResponse::Error(format!(
            "Signature has incorrect length: expected 64, got {}",
            signature_bytes_vec.len()
        ));
    }
    let signature_bytes: [u8; 64] = match <[u8; 64]>::try_from(signature_bytes_vec) {
        Ok(arr) => arr,
        Err(_) => return ApiResponse::Error("Failed to convert signature bytes".to_string()),
    };

    let signature = match Signature::try_from(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return ApiResponse::Error("Invalid signature bytes".to_string()),
    };

    let pubkey = match Pubkey::from_str(&payload.pubkey) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid base58 pubkey".to_string()),
    };

    let valid = signature.verify(pubkey.as_ref(), payload.message.as_bytes());

    let response_data = VerifyMessageResponseData {
        valid,
        message: payload.message,
        pubkey: payload.pubkey,
    };

    ApiResponse::Success(response_data)
}


#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponseData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

async fn send_sol_handler(raw_body: Bytes) -> impl IntoResponse {

    let payload: SendSolRequest = match serde_json::from_slice(&raw_body) {
        Ok(p) => p,
        Err(e) => {
            return ApiResponse::Error(format!("Invalid JSON or missing required fields: {}", e));
        }
    };


    if payload.lamports == 0 {
        return ApiResponse::Error("Lamports must be greater than zero".to_string());
    }


    let from_pubkey = match Pubkey::from_str(&payload.from) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid 'from' public key".to_string()),
    };


    let to_pubkey = match Pubkey::from_str(&payload.to) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid 'to' public key".to_string()),
    };


    let instruction: Instruction = system_instruction::transfer(&from_pubkey, &to_pubkey, payload.lamports);


    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| meta.pubkey.to_string())
        .collect::<Vec<_>>();


    let instruction_data = base64::encode(&instruction.data);

    let response_data = SendSolResponseData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };

    ApiResponse::Success(response_data)
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenAccountResponse {
    pubkey: String,
    isSigner: bool,
}

#[derive(Serialize)]
struct SendTokenResponseData {
    program_id: String,
    accounts: Vec<SendTokenAccountResponse>,
    instruction_data: String,
}

async fn send_token_handler(raw_body: Bytes) -> impl IntoResponse {
    // Deserialize JSON manually
    let payload: SendTokenRequest = match serde_json::from_slice(&raw_body) {
        Ok(p) => p,
        Err(e) => {
            return ApiResponse::Error(format!("Invalid JSON or missing required fields: {}", e));
        }
    };

    // Validate amount > 0
    if payload.amount == 0 {
        return ApiResponse::Error("Amount must be greater than zero".to_string());
    }

    // Parse pubkeys
    let destination = match Pubkey::from_str(&payload.destination) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid destination pubkey".to_string()),
    };

    let mint = match Pubkey::from_str(&payload.mint) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid mint pubkey".to_string()),
    };

    let owner = match Pubkey::from_str(&payload.owner) {
        Ok(pk) => pk,
        Err(_) => return ApiResponse::Error("Invalid owner pubkey".to_string()),
    };

    // Create SPL token transfer instruction
    let instruction = match transfer(
        &spl_token::id(),
        &destination,
        &mint,
        &owner,
        &[], // no multisig signers
        payload.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return ApiResponse::Error(format!("Failed to create transfer instruction: {}", e)),
    };

    // Map accounts to response format (pubkey + isSigner)
    let accounts = instruction
        .accounts
        .iter()
        .map(|meta| SendTokenAccountResponse {
            pubkey: meta.pubkey.to_string(),
            isSigner: meta.is_signer,
        })
        .collect::<Vec<_>>();

    // Base64 encode instruction data
    let instruction_data = base64::encode(&instruction.data);

    let response_data = SendTokenResponseData {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data,
    };

    ApiResponse::Success(response_data)
}
#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(keypair_handler))
        .route("/token/create", post(create_token_handler))
        .route("/token/mint", post(mint_token_handler))
        .route("/message/sign", post(sign_message_handler))
        .route("/message/verify", post(verify_message_handler))
        .route("/send/sol", post(send_sol_handler))
         .route("/send/token", post(send_token_handler));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server is running on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

