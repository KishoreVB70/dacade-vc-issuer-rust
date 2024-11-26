import type { Principal } from '@dfinity/principal';
import type { ActorMethod } from '@dfinity/agent';
import type { IDL } from '@dfinity/candid';

export type ArgumentValue = { 'Int' : number } |
  { 'String' : string };
export interface CredentialSpec {
  'arguments' : [] | [Array<[string, ArgumentValue]>],
  'credential_type' : string,
}
export interface DerivationOriginData { 'origin' : string }
export type DerivationOriginError = { 'Internal' : string } |
  { 'UnsupportedOrigin' : string };
export interface DerivationOriginRequest { 'frontend_hostname' : string }
export interface GetCredentialRequest {
  'signed_id_alias' : SignedIdAlias,
  'prepared_context' : [] | [Uint8Array | number[]],
  'credential_spec' : CredentialSpec,
}
export interface Icrc21ConsentInfo {
  'consent_message' : string,
  'language' : string,
}
export interface Icrc21ConsentPreferences { 'language' : string }
export type Icrc21Error = {
    'GenericError' : { 'description' : string, 'error_code' : bigint }
  } |
  { 'UnsupportedCanisterCall' : Icrc21ErrorInfo } |
  { 'ConsentMessageUnavailable' : Icrc21ErrorInfo };
export interface Icrc21ErrorInfo { 'description' : string }
export interface Icrc21VcConsentMessageRequest {
  'preferences' : Icrc21ConsentPreferences,
  'credential_spec' : CredentialSpec,
}
export type IssueCredentialError = { 'Internal' : string } |
  { 'SignatureNotFound' : string } |
  { 'InvalidIdAlias' : string } |
  { 'UnauthorizedSubject' : string } |
  { 'UnknownSubject' : string } |
  { 'UnsupportedCredentialSpec' : string };
export interface IssuedCredentialData { 'vc_jws' : string }
export interface IssuerInit {
  'derivation_origin' : string,
  'idp_canister_ids' : Array<Principal>,
  'ic_root_key_der' : Uint8Array | number[],
}
export interface PrepareCredentialRequest {
  'signed_id_alias' : SignedIdAlias,
  'credential_spec' : CredentialSpec,
}
export interface PreparedCredentialData {
  'prepared_context' : [] | [Uint8Array | number[]],
}
export type Result = { 'Ok' : string } |
  { 'Err' : string };
export type Result_1 = { 'Ok' : DerivationOriginData } |
  { 'Err' : DerivationOriginError };
export type Result_2 = { 'Ok' : IssuedCredentialData } |
  { 'Err' : IssueCredentialError };
export type Result_3 = { 'Ok' : PreparedCredentialData } |
  { 'Err' : IssueCredentialError };
export type Result_4 = { 'Ok' : Icrc21ConsentInfo } |
  { 'Err' : Icrc21Error };
export interface SignedIdAlias { 'credential_jws' : string }
export interface _SERVICE {
  'add_course' : ActorMethod<[string], Result>,
  'add_course_completion' : ActorMethod<[string], Result>,
  'derivation_origin' : ActorMethod<[DerivationOriginRequest], Result_1>,
  'get_credential' : ActorMethod<[GetCredentialRequest], Result_2>,
  'get_ii_id' : ActorMethod<[], string>,
  'has_completed_course' : ActorMethod<[string, Principal], boolean>,
  'prepare_credential' : ActorMethod<[PrepareCredentialRequest], Result_3>,
  'vc_consent_message' : ActorMethod<[Icrc21VcConsentMessageRequest], Result_4>,
}
export declare const idlFactory: IDL.InterfaceFactory;
export declare const init: (args: { IDL: typeof IDL }) => IDL.Type[];
