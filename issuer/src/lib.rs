use ic_cdk::export_candid;
use crate::init_upgrade::SettingsInput;
mod init_upgrade;
use base64::Engine;
use candid::{candid_method, Principal, CandidType, Deserialize};
use ic_canister_sig_creation::signature_map::{CanisterSigInputs, SignatureMap, LABEL_SIG};
use ic_canister_sig_creation::{
    extract_raw_root_pk_from_der, CanisterSigPublicKey, IC_ROOT_PK_DER,
};
use ic_cdk::api::{set_certified_data, time};
use ic_cdk::caller;
use ic_cdk_macros::{query, update};
use ic_certification::{labeled_hash, Hash};
use ic_verifiable_credentials::issuer_api::{
    ArgumentValue, CredentialSpec, DerivationOriginData, DerivationOriginError,
    DerivationOriginRequest, GetCredentialRequest, Icrc21ConsentInfo, Icrc21Error,
    Icrc21VcConsentMessageRequest, IssueCredentialError, IssuedCredentialData,
    PrepareCredentialRequest, PreparedCredentialData, SignedIdAlias,
};
use ic_verifiable_credentials::{
    build_credential_jwt, did_for_principal, get_verified_id_alias_from_jws,
    vc_jwt_to_jws, vc_signing_input, AliasTuple, CredentialParams,
    VC_SIGNING_INPUT_DOMAIN
};
use ic_stable_structures::{DefaultMemoryImpl, RestrictedMemory, StableBTreeMap, StableCell};
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::storable::{Storable, Bound};
use std::borrow::Cow;
use lazy_static::lazy_static;
use serde_bytes::ByteBuf;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

const ISSUER_URL: &str = "https://dacade.org";
const CREDENTIAL_URL_PREFIX: &str = "data:text/plain;charset=UTF-8,";
const MINUTE_NS: u64 = 60 * 1_000_000_000;
// The expiration of issued verifiable credentials.
const VC_EXPIRATION_PERIOD_NS: u64 = 15 * MINUTE_NS;
const PROD_II_CANISTER_ID: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";

// Define a wrapper around `HashSet<Principal>`
#[derive(Debug, Clone, Default, PartialEq, Eq, CandidType, Deserialize)]
pub struct UserSet(pub HashSet<Principal>);

type CourseId = String;
type CourseMap = StableBTreeMap<CourseId, UserSet, VirtualMemory<Memory>>;
type Memory = RestrictedMemory<DefaultMemoryImpl>;
type ConfigCell = StableCell<IssuerConfig, Memory>;
const COURSE_MEMORY_ID: MemoryId = MemoryId::new(0u8);


impl Storable for UserSet {
    fn to_bytes(&self) -> Cow<[u8]> {
        let serialized = candid::encode_one(self).expect("Failed to serialize UserSet");
        Cow::Owned(serialized)
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("Failed to deserialize UserSet")
    }

    const BOUND: Bound = Bound::Unbounded; // Specify that the size is dynamic
}

thread_local! {
    /// Stable structures
    // Static configuration of the canister set by init() or post_upgrade().
    static CONFIG: RefCell<ConfigCell> = RefCell::new(ConfigCell::init(config_memory(), IssuerConfig::default()).expect("failed to initialize stable cell"));

    static MEMORY_MANAGER: RefCell<MemoryManager<Memory>> =
    RefCell::new(MemoryManager::init(managed_memory()));

    static COURSE_COMPLETIONS: RefCell<CourseMap> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(COURSE_MEMORY_ID)),
        )
    );

    /// Non-stable structures
    // Canister signatures
    static SIGNATURES : RefCell<SignatureMap> = RefCell::new(SignatureMap::default());
}

/// Reserve the first stable memory page for the configuration stable cell.
fn config_memory() -> Memory {
    RestrictedMemory::new(DefaultMemoryImpl::default(), 0..1)
}

/// All the stable memory after the first page is managed by MemoryManager
fn managed_memory() -> Memory {
    RestrictedMemory::new(
        DefaultMemoryImpl::default(),
        1..ic_stable_structures::MAX_PAGES,
    )
}

lazy_static! {
    // Seed and public key used for signing the credentials.
    static ref CANISTER_SIG_SEED: Vec<u8> = hash_bytes("DacadeVcIssuer").to_vec();
    static ref CANISTER_SIG_PK: CanisterSigPublicKey = CanisterSigPublicKey::new(ic_cdk::id(), CANISTER_SIG_SEED.clone());
}

#[derive(CandidType, Deserialize)]
struct IssuerConfig {
    /// Root of trust for checking canister signatures.
    ic_root_key_raw: Vec<u8>,
    /// List of canister ids that are allowed to provide id alias credentials.
    idp_canister_ids: Vec<Principal>,
    /// The derivation origin to be used by the issuer.
    derivation_origin: String,
}

impl Storable for IssuerConfig {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(candid::encode_one(self).expect("failed to encode IssuerConfig"))
    }
    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        candid::decode_one(&bytes).expect("failed to decode IssuerConfig")
    }
    const BOUND: Bound = Bound::Unbounded;
}

impl Default for IssuerConfig {
    fn default() -> Self {
        let derivation_origin = format!("https://{}.icp0.io", ic_cdk::id().to_text());
        Self {
            ic_root_key_raw: extract_raw_root_pk_from_der(IC_ROOT_PK_DER)
                .expect("failed to extract raw root pk from der"),
            idp_canister_ids: vec![Principal::from_text(PROD_II_CANISTER_ID).unwrap()],
            derivation_origin: derivation_origin.clone(),
        }
    }
}

impl From<IssuerInit> for IssuerConfig {
    fn from(init: IssuerInit) -> Self {
        Self {
            ic_root_key_raw: extract_raw_root_pk_from_der(&init.ic_root_key_der)
                .expect("failed to extract raw root pk from der"),
            idp_canister_ids: init.idp_canister_ids,
            derivation_origin: init.derivation_origin,
        }
    }
}

#[derive(CandidType, Deserialize)]
struct IssuerInit {
    /// Root of trust for checking canister signatures.
    ic_root_key_der: Vec<u8>,
    /// List of canister ids that are allowed to provide id alias credentials.
    idp_canister_ids: Vec<Principal>,
    /// The derivation origin to be used by the issuer.
    derivation_origin: String,
}

fn hash_bytes(value: impl AsRef<[u8]>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(value.as_ref());
    hasher.finalize().into()
}

fn update_root_hash() {
    SIGNATURES.with_borrow(|sigs| {
        set_certified_data(&labeled_hash(LABEL_SIG, &sigs.root_hash()));
    })
}

pub fn format_credential_spec(spec: &CredentialSpec) -> String {
    let mut description = format!("# Credential Type\n{}\n", spec.credential_type);

    if let Some(arguments) = &spec.arguments {
        description.push_str("## Arguments\n");
        for (key, value) in arguments {
            let value_str = match value {
                ArgumentValue::String(s) => s.clone(),
                ArgumentValue::Int(i) => i.to_string(),
            };
            description.push_str(&format!("- **{}**: {}\n", key, value_str));
        }
    } else {
        description.push_str("## Arguments\nNone\n");
    }

    description
}

#[update]
fn add_course(course_id: String) -> Result<String, String> {
    COURSE_COMPLETIONS.with(|courses| {
        let mut courses = courses.borrow_mut();

        // Check if the course already exists
        if courses.contains_key(&course_id) {
            return Err(format!("Course '{}' already exists.", course_id));
        }

        // Insert the new course with an empty UserSet
        courses.insert(course_id.clone(), UserSet(HashSet::new()))
            .ok_or_else(|| format!("Failed to add course '{}': Insert failed.", course_id))?;

        Ok(format!("Course '{}' added successfully.", course_id))
    })
}

#[update]
#[candid_method]
fn add_course_completion(course_id: String) -> Result<String, String> {
    let user = caller();
    COURSE_COMPLETIONS.with(|courses| {
        let mut courses = courses.borrow_mut();

        // Convert course_id to uppercase
        let course_id_upper = course_id.to_ascii_uppercase();

        // Get the existing UserSet for the course
        let mut user_set = courses
            .get(&course_id_upper)
            .map(|u| u.clone())
            .ok_or_else(|| format!("Course '{}' does not exist.", course_id_upper))?;

        // Add the user to the UserSet
        if user_set.0.insert(user) {
            // Write the modified UserSet back into the map
            courses.insert(course_id_upper.clone(), user_set).ok_or_else(|| {
                format!(
                    "Failed to update course '{}': StableBTreeMap insertion error.",
                    course_id_upper
                )
            })?;

            Ok(format!(
                "User '{}' added to course '{}'.",
                user.to_text(),
                course_id_upper
            ))
        } else {
            Ok(format!(
                "User '{}' is already in course '{}'.",
                user.to_text(),
                course_id_upper
            ))
        }
    })
}

#[query]
#[candid_method]
fn has_completed_course(course_id: String, user_id: Principal) -> bool {
    COURSE_COMPLETIONS.with(|courses| {
        let courses = courses.borrow();

        // Convert course_id to uppercase for consistent lookups
        let course_id_upper = course_id.to_ascii_uppercase();

        // Retrieve the UserSet for the given course_id
        if let Some(user_set) = courses.get(&course_id_upper) {
            // Check if the user_id exists in the UserSet
            user_set.0.contains(&user_id)
        } else {
            // Return false if the course does not exist
            false
        }
    })
}

#[query]
#[candid_method]
fn get_ii_id() -> String {
    CONFIG.with_borrow(|config| {
        let config = config.get();
        let ii_canister_id = &config.idp_canister_ids[0];
        return String::from(ii_canister_id.to_text());
    })
}

#[update]
#[candid_method]
async fn vc_consent_message(
    req: Icrc21VcConsentMessageRequest,
) -> Result<Icrc21ConsentInfo, Icrc21Error> {
    Ok(Icrc21ConsentInfo {
        consent_message: format_credential_spec(&req.credential_spec),
        language: "en".to_string(),
    })
}

#[update]
#[candid_method]
async fn derivation_origin(
    req: DerivationOriginRequest,
) -> Result<DerivationOriginData, DerivationOriginError> {
    Ok(DerivationOriginData {
        origin: req.frontend_hostname,
    })
}

fn internal_error(msg: &str) -> IssueCredentialError {
    IssueCredentialError::Internal(String::from(msg))
}

/// Decodes a Verifiable Credential JWT and returns the value within `credentialSubject`.
/// This function doesn't perform any validation or signature verification.
fn get_alias_from_jwt(jwt_alias: &str) -> Result<Principal, &'static str> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
    let payload = jwt_alias
        .split('.')
        .skip(1)
        .next()
        .ok_or("Failed to parse JWT")?;
    let claims: Value = serde_json::from_slice(
        &BASE64
            .decode(payload)
            .map_err(|_| "Failed to decode base64")?,
    )
    .map_err(|_| "Failed to parse payload JSON")?;
    let alias = claims
        .pointer("/vc/credentialSubject/InternetIdentityIdAlias/hasIdAlias")
        .ok_or("Failed to extract alias")?
        .as_str()
        .ok_or("Invalid value for 'hasIdAlias'")?;
    Principal::from_text(alias).map_err(|_| "Failed to parse principal")
}

fn exp_timestamp_s() -> u32 {
    ((time() + VC_EXPIRATION_PERIOD_NS) / 1_000_000_000) as u32
}

// Prepares a unique id for the given subject_principal.
// The returned URL has the format: "data:text/plain;charset=UTF-8,issuer:...,timestamp_ns:...,subject:..."
fn credential_id_for_principal(subject_principal: Principal) -> String {
    let issuer = format!("issuer:{}", ISSUER_URL);
    let timestamp = format!("timestamp_ns:{}", time());
    let subject = format!("subject:{}", subject_principal.to_text());
    format!(
        "{}{},{},{}",
        CREDENTIAL_URL_PREFIX, issuer, timestamp, subject
    )
}

fn verified_credential(subject_principal: Principal, credential_spec: &CredentialSpec) -> String {
    let params = CredentialParams {
        spec: credential_spec.clone(),
        subject_id: did_for_principal(subject_principal),
        credential_id_url: credential_id_for_principal(subject_principal),
        issuer_url: ISSUER_URL.to_string(),
        expiration_timestamp_s: exp_timestamp_s(),
    };
    build_credential_jwt(params)
}

#[candid_method]
#[update]
async fn prepare_credential(
    req: PrepareCredentialRequest,
) -> Result<PreparedCredentialData, IssueCredentialError> {
    let alias_tuple = get_alias_tuple(&req.signed_id_alias, &caller(), time().into())?;

    let Ok(id_alias) = get_alias_from_jwt(&req.signed_id_alias.credential_jws) else {
        return Err(internal_error("Error getting id_alias"));
    };

    let user_principal: Principal  = alias_tuple.id_dapp;
    let mut course_id = match get_course_id_from_spec(&req.credential_spec) {
        Some(id) => id,
        None => return Err(IssueCredentialError::UnsupportedCredentialSpec("Missing course ID".to_string())),
    };

    course_id = course_id.to_ascii_uppercase();

    if !has_completed_course(course_id.clone(), user_principal) {
        return Err(IssueCredentialError::UnauthorizedSubject(format!("User {} has not completed {}", user_principal.to_text(), &course_id.to_string())));
    } 

    let credential_jwt = verified_credential(id_alias, &req.credential_spec);
    let signing_input =
        vc_signing_input(&credential_jwt, &CANISTER_SIG_PK).expect("failed getting signing_input");
    let sig_inputs = CanisterSigInputs {
        domain: VC_SIGNING_INPUT_DOMAIN,
        message: &signing_input,
        seed: &CANISTER_SIG_SEED,
    };
    SIGNATURES.with_borrow_mut(|sigs| sigs.add_signature(&sig_inputs));
    update_root_hash();
    Ok(PreparedCredentialData {
        prepared_context: Some(ByteBuf::from(credential_jwt.as_bytes())),
    })
}

/// Verifies the ID alias from the signed JWT and returns the alias tuple.
///
/// This function checks the validity of the provided JWS and ensures it matches the expected subject.
pub fn get_alias_tuple(
    alias: &SignedIdAlias,
    expected_vc_subject: &Principal,
    current_time_ns: u128,
) -> Result<AliasTuple, IssueCredentialError> {
    CONFIG.with_borrow(|config| {
        let config = config.get();

        let ii_canister_id = &config.idp_canister_ids[0];

        get_verified_id_alias_from_jws(
            &alias.credential_jws,
            expected_vc_subject,
            &ii_canister_id,
            &config.ic_root_key_raw,
            current_time_ns,
        )
        .map_err(|_| {
            IssueCredentialError::UnauthorizedSubject( format!("Expected caller {}", expected_vc_subject.to_text()))
        })
    })
}

fn get_course_id_from_spec(credential_spec: &CredentialSpec) -> Option<String> {
    // Check if the arguments field is Some and contains the HashMap
    if let Some(arguments) = &credential_spec.arguments {
        // Look for the course_id key in the arguments
        if let Some(ArgumentValue::String(course_id)) = arguments.get("course") {
            // Return the course ID if found
            return Some(course_id.clone());
        }
    }
    // Return None if the course ID is not found
    None
}

#[query]
#[candid_method(query)]
fn get_credential(req: GetCredentialRequest) -> Result<IssuedCredentialData, IssueCredentialError> {
    let prepared_context = match req.prepared_context {
        Some(context) => context,
        None => {
            return Result::<IssuedCredentialData, IssueCredentialError>::Err(internal_error(
                "missing prepared_context",
            ))
        }
    };
    let credential_jwt = match String::from_utf8(prepared_context.into_vec()) {
        Ok(s) => s,
        Err(_) => {
            return Result::<IssuedCredentialData, IssueCredentialError>::Err(internal_error(
                "invalid prepared_context",
            ))
        }
    };
    let signing_input =
        vc_signing_input(&credential_jwt, &CANISTER_SIG_PK).expect("failed getting signing_input");
    let sig_inputs = CanisterSigInputs {
        domain: VC_SIGNING_INPUT_DOMAIN,
        message: &signing_input,
        seed: &CANISTER_SIG_SEED,
    };
    let sig_result = SIGNATURES.with_borrow(|sigs| sigs.get_signature_as_cbor(&sig_inputs, None));
    let sig = match sig_result {
        Ok(sig) => sig,
        Err(e) => {
            return Result::<IssuedCredentialData, IssueCredentialError>::Err(
                IssueCredentialError::SignatureNotFound(format!(
                    "signature not prepared or expired: {}",
                    e
                )),
            );
        }
    };
    let vc_jws =
        vc_jwt_to_jws(&credential_jwt, &CANISTER_SIG_PK, &sig).expect("failed constructing JWS");
    Result::<IssuedCredentialData, IssueCredentialError>::Ok(IssuedCredentialData { vc_jws })
}
export_candid!();