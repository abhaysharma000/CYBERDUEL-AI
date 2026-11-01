/**
 * CyberDuel AI — Internal Runtime Message Protocols
 * Strictly typed schemas for message passing between Content Scripts, Popup, Options, and Service Worker.
 */

import { Decision, LocalThreatResult } from './contracts';
import { ExtensionSettings } from './storage';

export type MessageType =
  | 'EVALUATE_URL_REQUEST'
  | 'EVALUATE_URL_RESPONSE'
  | 'GET_PROTECTION_STATUS_REQUEST'
  | 'GET_PROTECTION_STATUS_RESPONSE'
  | 'TRIGGER_UPDATE_CHECK_REQUEST'
  | 'TRIGGER_UPDATE_CHECK_RESPONSE'
  | 'GET_SETTINGS_REQUEST'
  | 'GET_SETTINGS_RESPONSE'
  | 'UPDATE_SETTINGS_REQUEST'
  | 'UPDATE_SETTINGS_RESPONSE'
  | 'SUBMIT_FALSE_POSITIVE_REQUEST'
  | 'SUBMIT_FALSE_POSITIVE_RESPONSE'
  | 'CREATE_CONTINUATION_TOKEN_REQUEST'
  | 'CREATE_CONTINUATION_TOKEN_RESPONSE'
  | 'VALIDATE_CONTINUATION_TOKEN_REQUEST'
  | 'VALIDATE_CONTINUATION_TOKEN_RESPONSE'
  | 'RESET_FACTORY_POLICY_REQUEST'
  | 'RESET_FACTORY_POLICY_RESPONSE'
  | 'RECORD_LINKS_SCANNED_REQUEST'
  | 'RECORD_LINKS_SCANNED_RESPONSE';

export interface BaseMessage {
  type: MessageType;
  timestamp: string;
}

export interface EvaluateURLRequest extends BaseMessage {
  type: 'EVALUATE_URL_REQUEST';
  url: string;
  source: 'content_script' | 'popup_manual' | 'omnibox';
}

export interface EvaluateURLResponse extends BaseMessage {
  type: 'EVALUATE_URL_RESPONSE';
  url: string;
  result: LocalThreatResult;
}

export interface GetProtectionStatusRequest extends BaseMessage {
  type: 'GET_PROTECTION_STATUS_REQUEST';
}

export interface ProtectionStatusData {
  isEnabled: boolean;
  policyVersion: string;
  sequenceNumber: number;
  lastUpdateCheckedAt: string | null;
  lastUpdatedInstalledAt: string | null;
  isStale: boolean;
  cloudConnected: boolean;
  activeDNRRuleCount: number;
  recentEvaluationsCount: number;
  updateStatus: 'idle' | 'checking' | 'downloading' | 'verified' | 'installed' | 'error';
  lastErrorMessage?: string | null;
  scannedLinksCount: number;
  threatsBlockedCount: number;
}

export interface RecordLinksScannedRequest extends BaseMessage {
  type: 'RECORD_LINKS_SCANNED_REQUEST';
  count: number;
}

export interface RecordLinksScannedResponse extends BaseMessage {
  type: 'RECORD_LINKS_SCANNED_RESPONSE';
  scannedCount: number;
}

export interface GetProtectionStatusResponse extends BaseMessage {
  type: 'GET_PROTECTION_STATUS_RESPONSE';
  status: ProtectionStatusData;
}

export interface TriggerUpdateCheckRequest extends BaseMessage {
  type: 'TRIGGER_UPDATE_CHECK_REQUEST';
}

export interface TriggerUpdateCheckResponse extends BaseMessage {
  type: 'TRIGGER_UPDATE_CHECK_RESPONSE';
  success: boolean;
  message: string;
  updatedVersion?: string | null;
}

export interface GetSettingsRequest extends BaseMessage {
  type: 'GET_SETTINGS_REQUEST';
}

export interface GetSettingsResponse extends BaseMessage {
  type: 'GET_SETTINGS_RESPONSE';
  settings: ExtensionSettings;
}

export interface UpdateSettingsRequest extends BaseMessage {
  type: 'UPDATE_SETTINGS_REQUEST';
  settings: Partial<ExtensionSettings>;
}

export interface UpdateSettingsResponse extends BaseMessage {
  type: 'UPDATE_SETTINGS_RESPONSE';
  success: boolean;
  settings: ExtensionSettings;
}

export interface SubmitFalsePositiveRequest extends BaseMessage {
  type: 'SUBMIT_FALSE_POSITIVE_REQUEST';
  targetUrl: string;
  reportedDecision: Decision;
  reason: string;
}

export interface SubmitFalsePositiveResponse extends BaseMessage {
  type: 'SUBMIT_FALSE_POSITIVE_RESPONSE';
  success: boolean;
  message: string;
}

export interface CreateContinuationTokenRequest extends BaseMessage {
  type: 'CREATE_CONTINUATION_TOKEN_REQUEST';
  targetUrl: string;
}

export interface CreateContinuationTokenResponse extends BaseMessage {
  type: 'CREATE_CONTINUATION_TOKEN_RESPONSE';
  token: string;
  expiresAt: string;
}

export interface ValidateContinuationTokenRequest extends BaseMessage {
  type: 'VALIDATE_CONTINUATION_TOKEN_REQUEST';
  token: string;
  targetUrl: string;
}

export interface ValidateContinuationTokenResponse extends BaseMessage {
  type: 'VALIDATE_CONTINUATION_TOKEN_RESPONSE';
  isValid: boolean;
}

export interface ResetFactoryPolicyRequest extends BaseMessage {
  type: 'RESET_FACTORY_POLICY_REQUEST';
}

export interface ResetFactoryPolicyResponse extends BaseMessage {
  type: 'RESET_FACTORY_POLICY_RESPONSE';
  success: boolean;
  message: string;
}

export type ExtensionMessage =
  | EvaluateURLRequest
  | EvaluateURLResponse
  | GetProtectionStatusRequest
  | GetProtectionStatusResponse
  | TriggerUpdateCheckRequest
  | TriggerUpdateCheckResponse
  | GetSettingsRequest
  | GetSettingsResponse
  | UpdateSettingsRequest
  | UpdateSettingsResponse
  | SubmitFalsePositiveRequest
  | SubmitFalsePositiveResponse
  | CreateContinuationTokenRequest
  | CreateContinuationTokenResponse
  | ValidateContinuationTokenRequest
  | ValidateContinuationTokenResponse
  | ResetFactoryPolicyRequest
  | ResetFactoryPolicyResponse
  | RecordLinksScannedRequest
  | RecordLinksScannedResponse;
