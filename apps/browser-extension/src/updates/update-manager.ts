/**
 * CyberDuel AI — Staged Update Manager
 * Coordinates: available -> downloaded -> verified -> prepared -> installed -> acknowledged.
 */

import { UpdateClient } from './update-client';
import { PolicyStore } from '../storage/policy-store';
import { SettingsStore } from '../storage/settings-store';
import { FACTORY_TRUST_ANCHORS } from '../storage/factory-policy';
import { ClientUpdateVerifier } from '../crypto/verifier';
import { DNRRuleManager } from '../dnr/rule-manager';
import { ReleaseChannel, TrustAnchorSet, UpdateAcknowledgement } from '../types/contracts';

export interface UpdateExecutionResult {
  success: boolean;
  message: string;
  previousVersion?: string;
  newVersion?: string;
  sequenceNumber?: number;
}

export class UpdateManager {
  private client: UpdateClient;

  constructor(client?: UpdateClient) {
    this.client = client ?? new UpdateClient();
  }

  public async runUpdateCycle(): Promise<UpdateExecutionResult> {
    const settings = await SettingsStore.getSettings();
    this.client.setBaseUrl(settings.backend_base_url);

    const currentState = await PolicyStore.getState();
    const currentSeq = currentState.sequence_number;
    const currentVersion = currentState.active_policy.policy_version;

    await PolicyStore.recordUpdateStatus('checking');

    // 1. Check for updates
    let checkResp;
    try {
      checkResp = await this.client.checkForUpdates({
        client_id: settings.client_id,
        client_type: 'browser_extension',
        engine_version: '1.0.0',
        current_policy_version: currentVersion,
        current_sequence_number: currentSeq,
        channel: settings.channel as ReleaseChannel,
        platform: 'Chrome-130',
      });
    } catch (err) {
      const msg = `Cloud update check failed: ${err}`;
      await PolicyStore.recordUpdateStatus('error', msg);
      return { success: false, message: msg };
    }

    if (!checkResp.update_available || !checkResp.latest_version) {
      await PolicyStore.recordUpdateStatus('idle', null);
      return {
        success: true,
        message: 'Client policy is already up to date.',
        newVersion: currentVersion,
        sequenceNumber: currentSeq,
      };
    }

    // 2. Fetch trust anchors
    let trustAnchors: TrustAnchorSet;
    try {
      trustAnchors = await this.client.fetchTrustAnchors();
    } catch {
      // Fallback to factory trust anchors if backend trust anchor route is offline
      trustAnchors = FACTORY_TRUST_ANCHORS;
    }

    // 3. Download manifest
    await PolicyStore.recordUpdateStatus('downloading');
    let manifest;
    try {
      manifest = await this.client.fetchManifest(checkResp.latest_version);
    } catch (err) {
      const msg = `Failed to download manifest: ${err}`;
      await PolicyStore.recordUpdateStatus('error', msg);
      return { success: false, message: msg };
    }

    // 4. Download artifact bundle
    let artifactData;
    try {
      artifactData = await this.client.fetchArtifact(manifest.artifact_digest);
    } catch (err) {
      const msg = `Failed to download policy artifact: ${err}`;
      await PolicyStore.recordUpdateStatus('error', msg);
      return { success: false, message: msg };
    }

    // 5. Run 7-Step Verification
    const verifier = new ClientUpdateVerifier({
      currentSequence: currentSeq,
      currentPolicyVersion: currentVersion,
      clientVersion: '1.0.0',
      engineVersion: '1.0.0',
    });

    const verificationResult = verifier.verify(
      manifest,
      artifactData.rawText,
      artifactData.bundle,
      trustAnchors
    );

    if (!verificationResult.isValid) {
      const failReason = `${verificationResult.stepFailed}: ${verificationResult.errorMessage}`;
      await PolicyStore.recordUpdateStatus('error', failReason);

      // Send honest failure acknowledgement
      const failAck: UpdateAcknowledgement = {
        acknowledgement_id: 'ack-' + Math.random().toString(36).substring(2, 10),
        client_id: settings.client_id,
        release_id: manifest.release_id,
        policy_version: manifest.policy_version,
        sequence_number: manifest.sequence_number,
        status: 'failed',
        error_message: failReason,
        is_rollback_applied: false,
        channel: manifest.channel,
        reported_at: new Date().toISOString(),
      };
      await this.client.sendAcknowledgement(failAck);

      return {
        success: false,
        message: `Policy verification rejected: ${failReason}`,
      };
    }

    await PolicyStore.recordUpdateStatus('verified');

    // 6. Prepare & Install DNR Rules
    try {
      await DNRRuleManager.installPolicyRules(artifactData.bundle);
    } catch (err) {
      const dnrError = `DNR rule compilation or installation error: ${err}`;
      await PolicyStore.recordUpdateStatus('error', dnrError);

      const failAck: UpdateAcknowledgement = {
        acknowledgement_id: 'ack-' + Math.random().toString(36).substring(2, 10),
        client_id: settings.client_id,
        release_id: manifest.release_id,
        policy_version: manifest.policy_version,
        sequence_number: manifest.sequence_number,
        status: 'failed',
        error_message: dnrError,
        is_rollback_applied: false,
        channel: manifest.channel,
        reported_at: new Date().toISOString(),
      };
      await this.client.sendAcknowledgement(failAck);

      return {
        success: false,
        message: dnrError,
      };
    }

    // 7. Commit New Policy State
    await PolicyStore.commitNewPolicy(artifactData.bundle, manifest);

    // 8. Send Successful Acknowledgement Receipt
    const successAck: UpdateAcknowledgement = {
      acknowledgement_id: 'ack-' + Math.random().toString(36).substring(2, 10),
      client_id: settings.client_id,
      release_id: manifest.release_id,
      policy_version: manifest.policy_version,
      sequence_number: manifest.sequence_number,
      status: manifest.is_rollback ? 'rolled_back' : 'installed',
      error_message: null,
      is_rollback_applied: manifest.is_rollback,
      channel: manifest.channel,
      reported_at: new Date().toISOString(),
    };
    await this.client.sendAcknowledgement(successAck);

    return {
      success: true,
      message: `Successfully installed verified policy ${manifest.policy_version} (Seq ${manifest.sequence_number})`,
      previousVersion: currentVersion,
      newVersion: manifest.policy_version,
      sequenceNumber: manifest.sequence_number,
    };
  }
}

