//! Identity-bound durable leases for generated follow-up queue items.
//!
//! This module is deliberately persistence- and clock-agnostic. Callers place
//! [`LeaseEvent`] values in the authenticated queue journal and feed the
//! journal's explicit time observations to this deterministic reducer. The
//! durable effect-start transition is a fencing boundary: after it, no release
//! or reclaim can make the work executable again.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Deserializer, Serialize};

const MAX_CANONICAL_ID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct WorkerIdentity(String);

impl WorkerIdentity {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_canonical_identifier(&value, "worker identity")?;
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for WorkerIdentity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct LeaseIdentity(String);

impl LeaseIdentity {
    pub(crate) fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_canonical_identifier(&value, "lease identity")?;
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for LeaseIdentity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseProof {
    worker: WorkerIdentity,
    lease_id: LeaseIdentity,
    generation: u64,
}

impl LeaseProof {
    pub(crate) fn new(
        worker: WorkerIdentity,
        lease_id: LeaseIdentity,
        generation: u64,
    ) -> Result<Self> {
        let proof = Self {
            worker,
            lease_id,
            generation,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub(crate) fn worker(&self) -> &WorkerIdentity {
        &self.worker
    }

    pub(crate) fn lease_id(&self) -> &LeaseIdentity {
        &self.lease_id
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    fn validate(&self) -> Result<()> {
        validate_canonical_identifier(self.worker.as_str(), "worker identity")?;
        validate_canonical_identifier(self.lease_id.as_str(), "lease identity")?;
        if self.generation == 0 {
            bail!("lease proof generation must be nonzero");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseProofWire {
    worker: WorkerIdentity,
    lease_id: LeaseIdentity,
    generation: u64,
}

impl TryFrom<LeaseProofWire> for LeaseProof {
    type Error = anyhow::Error;

    fn try_from(wire: LeaseProofWire) -> Result<Self> {
        Self::new(wire.worker, wire.lease_id, wire.generation)
    }
}

impl<'de> Deserialize<'de> for LeaseProof {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        LeaseProofWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

/// The bounded, latest-only lineage retained after a stale lease is reclaimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseReclaimLineage {
    predecessor: LeaseProof,
    predecessor_expires_at: u64,
    reclaimed_at: u64,
    successor: LeaseProof,
}

impl LeaseReclaimLineage {
    pub(crate) fn new(
        predecessor: LeaseProof,
        predecessor_expires_at: u64,
        reclaimed_at: u64,
        successor: LeaseProof,
    ) -> Result<Self> {
        let lineage = Self {
            predecessor,
            predecessor_expires_at,
            reclaimed_at,
            successor,
        };
        lineage.validate()?;
        Ok(lineage)
    }

    pub(crate) fn predecessor(&self) -> &LeaseProof {
        &self.predecessor
    }

    pub(crate) fn predecessor_expires_at(&self) -> u64 {
        self.predecessor_expires_at
    }

    pub(crate) fn reclaimed_at(&self) -> u64 {
        self.reclaimed_at
    }

    pub(crate) fn successor(&self) -> &LeaseProof {
        &self.successor
    }

    fn validate(&self) -> Result<()> {
        self.predecessor.validate()?;
        self.successor.validate()?;
        if self.reclaimed_at < self.predecessor_expires_at {
            bail!("lease reclaim observation precedes predecessor expiry");
        }
        let expected_generation = self
            .predecessor
            .generation
            .checked_add(1)
            .context("lease generation overflowed during reclaim")?;
        if self.successor.generation != expected_generation {
            bail!("reclaimed lease does not use the exact successor generation");
        }
        if self.successor.lease_id == self.predecessor.lease_id {
            bail!("reclaimed lease must use a distinct lease identity");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseReclaimLineageWire {
    predecessor: LeaseProof,
    predecessor_expires_at: u64,
    reclaimed_at: u64,
    successor: LeaseProof,
}

impl TryFrom<LeaseReclaimLineageWire> for LeaseReclaimLineage {
    type Error = anyhow::Error;

    fn try_from(wire: LeaseReclaimLineageWire) -> Result<Self> {
        Self::new(
            wire.predecessor,
            wire.predecessor_expires_at,
            wire.reclaimed_at,
            wire.successor,
        )
    }
}

impl<'de> Deserialize<'de> for LeaseReclaimLineage {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        LeaseReclaimLineageWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseGrant {
    proof: LeaseProof,
    observed_at: u64,
    expires_at: u64,
}

impl LeaseGrant {
    fn new(proof: LeaseProof, observed_at: u64, expires_at: u64) -> Result<Self> {
        let grant = Self {
            proof,
            observed_at,
            expires_at,
        };
        grant.validate()?;
        Ok(grant)
    }

    fn validate(&self) -> Result<()> {
        self.proof.validate()?;
        if self.expires_at <= self.observed_at {
            bail!("lease grant expiry must be strictly after its observation");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseGrantWire {
    proof: LeaseProof,
    observed_at: u64,
    expires_at: u64,
}

impl TryFrom<LeaseGrantWire> for LeaseGrant {
    type Error = anyhow::Error;

    fn try_from(wire: LeaseGrantWire) -> Result<Self> {
        Self::new(wire.proof, wire.observed_at, wire.expires_at)
    }
}

impl<'de> Deserialize<'de> for LeaseGrant {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        LeaseGrantWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseHeartbeat {
    proof: LeaseProof,
    observed_at: u64,
    expires_at: u64,
}

impl LeaseHeartbeat {
    fn new(proof: LeaseProof, observed_at: u64, expires_at: u64) -> Result<Self> {
        let heartbeat = Self {
            proof,
            observed_at,
            expires_at,
        };
        heartbeat.validate()?;
        Ok(heartbeat)
    }

    fn validate(&self) -> Result<()> {
        self.proof.validate()?;
        if self.expires_at <= self.observed_at {
            bail!("heartbeat expiry must be strictly after its observation");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseHeartbeatWire {
    proof: LeaseProof,
    observed_at: u64,
    expires_at: u64,
}

impl TryFrom<LeaseHeartbeatWire> for LeaseHeartbeat {
    type Error = anyhow::Error;

    fn try_from(wire: LeaseHeartbeatWire) -> Result<Self> {
        Self::new(wire.proof, wire.observed_at, wire.expires_at)
    }
}

impl<'de> Deserialize<'de> for LeaseHeartbeat {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        LeaseHeartbeatWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseBoundObservation {
    proof: LeaseProof,
    observed_at: u64,
}

impl LeaseBoundObservation {
    fn new(proof: LeaseProof, observed_at: u64) -> Result<Self> {
        proof.validate()?;
        Ok(Self { proof, observed_at })
    }

    fn validate(&self) -> Result<()> {
        self.proof.validate()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseBoundObservationWire {
    proof: LeaseProof,
    observed_at: u64,
}

impl TryFrom<LeaseBoundObservationWire> for LeaseBoundObservation {
    type Error = anyhow::Error;

    fn try_from(wire: LeaseBoundObservationWire) -> Result<Self> {
        Self::new(wire.proof, wire.observed_at)
    }
}

impl<'de> Deserialize<'de> for LeaseBoundObservation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        LeaseBoundObservationWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseReclaim {
    lineage: LeaseReclaimLineage,
    successor_expires_at: u64,
}

impl LeaseReclaim {
    fn new(lineage: LeaseReclaimLineage, successor_expires_at: u64) -> Result<Self> {
        let reclaim = Self {
            lineage,
            successor_expires_at,
        };
        reclaim.validate()?;
        Ok(reclaim)
    }

    fn validate(&self) -> Result<()> {
        self.lineage.validate()?;
        if self.successor_expires_at <= self.lineage.reclaimed_at {
            bail!("reclaimed lease expiry must be strictly after its observation");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseReclaimWire {
    lineage: LeaseReclaimLineage,
    successor_expires_at: u64,
}

impl TryFrom<LeaseReclaimWire> for LeaseReclaim {
    type Error = anyhow::Error;

    fn try_from(wire: LeaseReclaimWire) -> Result<Self> {
        Self::new(wire.lineage, wire.successor_expires_at)
    }
}

impl<'de> Deserialize<'de> for LeaseReclaim {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        LeaseReclaimWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

/// Durable events intended to be embedded in the queue's authenticated event.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    tag = "event",
    content = "data",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum LeaseEvent {
    Claimed(LeaseGrant),
    Heartbeat(LeaseHeartbeat),
    Released(LeaseBoundObservation),
    Reclaimed(LeaseReclaim),
    EffectStarted(LeaseBoundObservation),
    Acknowledged(LeaseBoundObservation),
}

impl LeaseEvent {
    pub(crate) fn claimed(proof: LeaseProof, observed_at: u64, expires_at: u64) -> Result<Self> {
        Ok(Self::Claimed(LeaseGrant::new(
            proof,
            observed_at,
            expires_at,
        )?))
    }

    pub(crate) fn heartbeat(proof: LeaseProof, observed_at: u64, expires_at: u64) -> Result<Self> {
        Ok(Self::Heartbeat(LeaseHeartbeat::new(
            proof,
            observed_at,
            expires_at,
        )?))
    }

    pub(crate) fn released(proof: LeaseProof, observed_at: u64) -> Result<Self> {
        Ok(Self::Released(LeaseBoundObservation::new(
            proof,
            observed_at,
        )?))
    }

    pub(crate) fn reclaimed(
        predecessor: LeaseProof,
        predecessor_expires_at: u64,
        observed_at: u64,
        successor: LeaseProof,
        successor_expires_at: u64,
    ) -> Result<Self> {
        let lineage =
            LeaseReclaimLineage::new(predecessor, predecessor_expires_at, observed_at, successor)?;
        Ok(Self::Reclaimed(LeaseReclaim::new(
            lineage,
            successor_expires_at,
        )?))
    }

    pub(crate) fn effect_started(proof: LeaseProof, observed_at: u64) -> Result<Self> {
        Ok(Self::EffectStarted(LeaseBoundObservation::new(
            proof,
            observed_at,
        )?))
    }

    pub(crate) fn acknowledged(proof: LeaseProof, observed_at: u64) -> Result<Self> {
        Ok(Self::Acknowledged(LeaseBoundObservation::new(
            proof,
            observed_at,
        )?))
    }

    pub(crate) fn resulting_proof(&self) -> &LeaseProof {
        match self {
            Self::Claimed(grant) => &grant.proof,
            Self::Heartbeat(heartbeat) => &heartbeat.proof,
            Self::Released(observation)
            | Self::EffectStarted(observation)
            | Self::Acknowledged(observation) => &observation.proof,
            Self::Reclaimed(reclaim) => reclaim.lineage.successor(),
        }
    }

    pub(crate) fn observed_at(&self) -> u64 {
        match self {
            Self::Claimed(grant) => grant.observed_at,
            Self::Heartbeat(heartbeat) => heartbeat.observed_at,
            Self::Released(observation)
            | Self::EffectStarted(observation)
            | Self::Acknowledged(observation) => observation.observed_at,
            Self::Reclaimed(reclaim) => reclaim.lineage.reclaimed_at(),
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Claimed(grant) => grant.validate(),
            Self::Heartbeat(heartbeat) => heartbeat.validate(),
            Self::Released(observation)
            | Self::EffectStarted(observation)
            | Self::Acknowledged(observation) => observation.validate(),
            Self::Reclaimed(reclaim) => reclaim.validate(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeasePhase {
    Available,
    Active,
    EffectFenced,
    Acknowledged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AvailableLease {
    last_generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_observed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_reclaim: Option<LeaseReclaimLineage>,
}

impl AvailableLease {
    fn initial() -> Self {
        Self {
            last_generation: 0,
            last_observed_at: None,
            last_reclaim: None,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.last_generation == 0 {
            if self.last_observed_at.is_some() || self.last_reclaim.is_some() {
                bail!("initial available lease state contains transition evidence");
            }
            return Ok(());
        }
        let observed_at = self
            .last_observed_at
            .context("used available lease state omits its last observation")?;
        validate_retained_lineage(
            self.last_reclaim.as_ref(),
            self.last_generation,
            observed_at,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AvailableLeaseWire {
    last_generation: u64,
    #[serde(default)]
    last_observed_at: Option<u64>,
    #[serde(default)]
    last_reclaim: Option<LeaseReclaimLineage>,
}

impl TryFrom<AvailableLeaseWire> for AvailableLease {
    type Error = anyhow::Error;

    fn try_from(wire: AvailableLeaseWire) -> Result<Self> {
        let available = Self {
            last_generation: wire.last_generation,
            last_observed_at: wire.last_observed_at,
            last_reclaim: wire.last_reclaim,
        };
        available.validate()?;
        Ok(available)
    }
}

impl<'de> Deserialize<'de> for AvailableLease {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        AvailableLeaseWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveLease {
    proof: LeaseProof,
    issued_at: u64,
    last_heartbeat_at: u64,
    expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_reclaim: Option<LeaseReclaimLineage>,
}

impl ActiveLease {
    fn validate(&self) -> Result<()> {
        self.proof.validate()?;
        if self.last_heartbeat_at < self.issued_at {
            bail!("active lease heartbeat precedes issuance");
        }
        if self.expires_at <= self.last_heartbeat_at {
            bail!("active lease is not live at its last heartbeat");
        }
        validate_retained_lineage(
            self.last_reclaim.as_ref(),
            self.proof.generation,
            self.issued_at,
        )?;
        if let Some(lineage) = &self.last_reclaim {
            if lineage.successor.generation == self.proof.generation
                && (lineage.successor != self.proof || lineage.reclaimed_at != self.issued_at)
            {
                bail!("current reclaimed lease does not match its retained successor lineage");
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveLeaseWire {
    proof: LeaseProof,
    issued_at: u64,
    last_heartbeat_at: u64,
    expires_at: u64,
    #[serde(default)]
    last_reclaim: Option<LeaseReclaimLineage>,
}

impl TryFrom<ActiveLeaseWire> for ActiveLease {
    type Error = anyhow::Error;

    fn try_from(wire: ActiveLeaseWire) -> Result<Self> {
        let active = Self {
            proof: wire.proof,
            issued_at: wire.issued_at,
            last_heartbeat_at: wire.last_heartbeat_at,
            expires_at: wire.expires_at,
            last_reclaim: wire.last_reclaim,
        };
        active.validate()?;
        Ok(active)
    }
}

impl<'de> Deserialize<'de> for ActiveLease {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        ActiveLeaseWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EffectFencedLease {
    active: ActiveLease,
    effect_started_at: u64,
}

impl EffectFencedLease {
    fn validate(&self) -> Result<()> {
        self.active.validate()?;
        if self.effect_started_at <= self.active.last_heartbeat_at {
            bail!("effect start does not strictly advance lease time");
        }
        if self.effect_started_at >= self.active.expires_at {
            bail!("effect start was observed on an expired lease");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectFencedLeaseWire {
    active: ActiveLease,
    effect_started_at: u64,
}

impl TryFrom<EffectFencedLeaseWire> for EffectFencedLease {
    type Error = anyhow::Error;

    fn try_from(wire: EffectFencedLeaseWire) -> Result<Self> {
        let fenced = Self {
            active: wire.active,
            effect_started_at: wire.effect_started_at,
        };
        fenced.validate()?;
        Ok(fenced)
    }
}

impl<'de> Deserialize<'de> for EffectFencedLease {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        EffectFencedLeaseWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AcknowledgedLease {
    fence: EffectFencedLease,
    acknowledged_at: u64,
}

impl AcknowledgedLease {
    fn validate(&self) -> Result<()> {
        self.fence.validate()?;
        if self.acknowledged_at < self.fence.effect_started_at {
            bail!("lease acknowledgement precedes effect start");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgedLeaseWire {
    fence: EffectFencedLease,
    acknowledged_at: u64,
}

impl TryFrom<AcknowledgedLeaseWire> for AcknowledgedLease {
    type Error = anyhow::Error;

    fn try_from(wire: AcknowledgedLeaseWire) -> Result<Self> {
        let acknowledged = Self {
            fence: wire.fence,
            acknowledged_at: wire.acknowledged_at,
        };
        acknowledged.validate()?;
        Ok(acknowledged)
    }
}

impl<'de> Deserialize<'de> for AcknowledgedLease {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        AcknowledgedLeaseWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

/// Replay-derived lease state. Only journal events should mutate this value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    tag = "phase",
    content = "lease",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum LeaseState {
    Available(AvailableLease),
    Active(ActiveLease),
    EffectFenced(EffectFencedLease),
    Acknowledged(AcknowledgedLease),
}

impl LeaseState {
    pub(crate) fn initial() -> Self {
        Self::Available(AvailableLease::initial())
    }

    pub(crate) fn replay<'a>(events: impl IntoIterator<Item = &'a LeaseEvent>) -> Result<Self> {
        let mut state = Self::initial();
        for event in events {
            state.apply(event)?;
        }
        Ok(state)
    }

    /// Applies one event atomically. A rejected event leaves `self` unchanged.
    pub(crate) fn apply(&mut self, event: &LeaseEvent) -> Result<()> {
        event.validate()?;
        let mut next = self.clone();
        next.apply_in_place(event)?;
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn phase(&self) -> LeasePhase {
        match self {
            Self::Available(_) => LeasePhase::Available,
            Self::Active(_) => LeasePhase::Active,
            Self::EffectFenced(_) => LeasePhase::EffectFenced,
            Self::Acknowledged(_) => LeasePhase::Acknowledged,
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        match self {
            Self::Available(available) => available.last_generation,
            Self::Active(active) => active.proof.generation,
            Self::EffectFenced(fenced) => fenced.active.proof.generation,
            Self::Acknowledged(acknowledged) => acknowledged.fence.active.proof.generation,
        }
    }

    pub(crate) fn active_proof(&self) -> Option<&LeaseProof> {
        match self {
            Self::Available(_) => None,
            Self::Active(active) => Some(&active.proof),
            Self::EffectFenced(fenced) => Some(&fenced.active.proof),
            Self::Acknowledged(acknowledged) => Some(&acknowledged.fence.active.proof),
        }
    }

    pub(crate) fn expires_at(&self) -> Option<u64> {
        match self {
            Self::Available(_) => None,
            Self::Active(active) => Some(active.expires_at),
            Self::EffectFenced(fenced) => Some(fenced.active.expires_at),
            Self::Acknowledged(acknowledged) => Some(acknowledged.fence.active.expires_at),
        }
    }

    pub(crate) fn issued_at(&self) -> Option<u64> {
        match self {
            Self::Available(_) => None,
            Self::Active(active) => Some(active.issued_at),
            Self::EffectFenced(fenced) => Some(fenced.active.issued_at),
            Self::Acknowledged(acknowledged) => Some(acknowledged.fence.active.issued_at),
        }
    }

    pub(crate) fn last_heartbeat_at(&self) -> Option<u64> {
        match self {
            Self::Available(_) => None,
            Self::Active(active) => Some(active.last_heartbeat_at),
            Self::EffectFenced(fenced) => Some(fenced.active.last_heartbeat_at),
            Self::Acknowledged(acknowledged) => Some(acknowledged.fence.active.last_heartbeat_at),
        }
    }

    /// Latest durable time observation represented by the derived state.
    pub(crate) fn last_observed_at(&self) -> Option<u64> {
        match self {
            Self::Available(available) => available.last_observed_at,
            Self::Active(active) => Some(active.last_heartbeat_at),
            Self::EffectFenced(fenced) => Some(fenced.effect_started_at),
            Self::Acknowledged(acknowledged) => Some(acknowledged.acknowledged_at),
        }
    }

    pub(crate) fn last_reclaim(&self) -> Option<&LeaseReclaimLineage> {
        match self {
            Self::Available(available) => available.last_reclaim.as_ref(),
            Self::Active(active) => active.last_reclaim.as_ref(),
            Self::EffectFenced(fenced) => fenced.active.last_reclaim.as_ref(),
            Self::Acknowledged(acknowledged) => acknowledged.fence.active.last_reclaim.as_ref(),
        }
    }

    pub(crate) fn effect_started_at(&self) -> Option<u64> {
        match self {
            Self::EffectFenced(fenced) => Some(fenced.effect_started_at),
            Self::Acknowledged(acknowledged) => Some(acknowledged.fence.effect_started_at),
            Self::Available(_) | Self::Active(_) => None,
        }
    }

    pub(crate) fn acknowledged_at(&self) -> Option<u64> {
        match self {
            Self::Acknowledged(acknowledged) => Some(acknowledged.acknowledged_at),
            Self::Available(_) | Self::Active(_) | Self::EffectFenced(_) => None,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Available(available) => available.validate(),
            Self::Active(active) => active.validate(),
            Self::EffectFenced(fenced) => fenced.validate(),
            Self::Acknowledged(acknowledged) => acknowledged.validate(),
        }
    }

    fn apply_in_place(&mut self, event: &LeaseEvent) -> Result<()> {
        match event {
            LeaseEvent::Claimed(grant) => self.apply_claim(grant),
            LeaseEvent::Heartbeat(heartbeat) => self.apply_heartbeat(heartbeat),
            LeaseEvent::Released(observation) => self.apply_release(observation),
            LeaseEvent::Reclaimed(reclaim) => self.apply_reclaim(reclaim),
            LeaseEvent::EffectStarted(observation) => self.apply_effect_start(observation),
            LeaseEvent::Acknowledged(observation) => self.apply_acknowledgement(observation),
        }
    }

    fn apply_claim(&mut self, grant: &LeaseGrant) -> Result<()> {
        let Self::Available(available) = self else {
            bail!("lease claim requires available state");
        };
        if let Some(last_observed_at) = available.last_observed_at {
            require_strict_time_advance(last_observed_at, grant.observed_at, "lease claim")?;
        }
        let expected_generation = available
            .last_generation
            .checked_add(1)
            .context("lease generation overflowed during claim")?;
        if grant.proof.generation != expected_generation {
            bail!("lease claim does not use the exact next generation");
        }
        *self = Self::Active(ActiveLease {
            proof: grant.proof.clone(),
            issued_at: grant.observed_at,
            last_heartbeat_at: grant.observed_at,
            expires_at: grant.expires_at,
            last_reclaim: available.last_reclaim.clone(),
        });
        Ok(())
    }

    fn apply_heartbeat(&mut self, heartbeat: &LeaseHeartbeat) -> Result<()> {
        let Self::Active(active) = self else {
            bail!("lease heartbeat requires an unfenced active lease");
        };
        require_exact_proof(&active.proof, &heartbeat.proof, "lease heartbeat")?;
        require_live_observation(active, heartbeat.observed_at, "lease heartbeat")?;
        if heartbeat.expires_at < active.expires_at {
            bail!("lease heartbeat cannot shorten expiry");
        }
        active.last_heartbeat_at = heartbeat.observed_at;
        active.expires_at = heartbeat.expires_at;
        Ok(())
    }

    fn apply_release(&mut self, observation: &LeaseBoundObservation) -> Result<()> {
        let Self::Active(active) = self else {
            bail!("lease release requires an unfenced active lease");
        };
        require_exact_proof(&active.proof, &observation.proof, "lease release")?;
        require_live_observation(active, observation.observed_at, "lease release")?;
        *self = Self::Available(AvailableLease {
            last_generation: active.proof.generation,
            last_observed_at: Some(observation.observed_at),
            last_reclaim: active.last_reclaim.clone(),
        });
        Ok(())
    }

    fn apply_reclaim(&mut self, reclaim: &LeaseReclaim) -> Result<()> {
        let Self::Active(active) = self else {
            bail!("lease reclaim requires an unfenced active predecessor");
        };
        let lineage = &reclaim.lineage;
        require_exact_proof(
            &active.proof,
            &lineage.predecessor,
            "lease reclaim predecessor",
        )?;
        if lineage.predecessor_expires_at != active.expires_at {
            bail!("lease reclaim predecessor expiry does not match durable active state");
        }
        if lineage.reclaimed_at < active.expires_at {
            bail!("lease reclaim was observed before predecessor expiry");
        }
        let expected_generation = active
            .proof
            .generation
            .checked_add(1)
            .context("lease generation overflowed during reclaim")?;
        if lineage.successor.generation != expected_generation {
            bail!("lease reclaim does not use the exact next generation");
        }
        *self = Self::Active(ActiveLease {
            proof: lineage.successor.clone(),
            issued_at: lineage.reclaimed_at,
            last_heartbeat_at: lineage.reclaimed_at,
            expires_at: reclaim.successor_expires_at,
            last_reclaim: Some(lineage.clone()),
        });
        Ok(())
    }

    fn apply_effect_start(&mut self, observation: &LeaseBoundObservation) -> Result<()> {
        let Self::Active(active) = self else {
            bail!("effect start requires an unfenced active lease");
        };
        require_exact_proof(&active.proof, &observation.proof, "effect start")?;
        require_live_observation(active, observation.observed_at, "effect start")?;
        *self = Self::EffectFenced(EffectFencedLease {
            active: active.clone(),
            effect_started_at: observation.observed_at,
        });
        Ok(())
    }

    fn apply_acknowledgement(&mut self, observation: &LeaseBoundObservation) -> Result<()> {
        let Self::EffectFenced(fence) = self else {
            bail!("acknowledgement requires a durably effect-fenced lease");
        };
        require_exact_proof(
            &fence.active.proof,
            &observation.proof,
            "lease acknowledgement",
        )?;
        if observation.observed_at < fence.effect_started_at {
            bail!("lease acknowledgement time moved backward");
        }
        *self = Self::Acknowledged(AcknowledgedLease {
            fence: fence.clone(),
            acknowledged_at: observation.observed_at,
        });
        Ok(())
    }
}

fn require_exact_proof(expected: &LeaseProof, presented: &LeaseProof, action: &str) -> Result<()> {
    if presented != expected {
        bail!("{action} does not prove the exact active worker lease and generation");
    }
    Ok(())
}

fn require_live_observation(active: &ActiveLease, observed_at: u64, action: &str) -> Result<()> {
    require_strict_time_advance(active.last_heartbeat_at, observed_at, action)?;
    if observed_at >= active.expires_at {
        bail!("{action} was observed on an expired lease");
    }
    Ok(())
}

fn require_strict_time_advance(previous: u64, observed_at: u64, action: &str) -> Result<()> {
    if observed_at <= previous {
        bail!("{action} time did not strictly advance");
    }
    Ok(())
}

fn validate_retained_lineage(
    lineage: Option<&LeaseReclaimLineage>,
    current_generation: u64,
    current_observed_at: u64,
) -> Result<()> {
    let Some(lineage) = lineage else {
        return Ok(());
    };
    lineage.validate()?;
    if lineage.successor.generation > current_generation {
        bail!("retained reclaim lineage is newer than current lease generation");
    }
    if lineage.reclaimed_at > current_observed_at {
        bail!("retained reclaim lineage is newer than current lease observation");
    }
    Ok(())
}

fn validate_canonical_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_CANONICAL_ID_BYTES
        || matches!(value, "." | "..")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{label} is not a bounded canonical identifier");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn worker(value: &str) -> WorkerIdentity {
        WorkerIdentity::new(value).expect("valid worker")
    }

    fn lease(value: &str) -> LeaseIdentity {
        LeaseIdentity::new(value).expect("valid lease")
    }

    fn proof(worker_id: &str, lease_id: &str, generation: u64) -> LeaseProof {
        LeaseProof::new(worker(worker_id), lease(lease_id), generation).expect("valid proof")
    }

    fn apply(state: &mut LeaseState, event: LeaseEvent) {
        state.apply(&event).expect("valid transition");
    }

    fn assert_rejected_atomically(state: &mut LeaseState, event: &LeaseEvent) {
        let original = state.clone();
        assert!(state.apply(event).is_err());
        assert_eq!(*state, original);
    }

    #[test]
    fn claim_heartbeat_effect_start_and_late_acknowledgement_are_valid() {
        let active = proof("worker-a", "lease-a", 1);
        assert_eq!(active.worker().as_str(), "worker-a");
        assert_eq!(active.lease_id().as_str(), "lease-a");
        assert_eq!(active.generation(), 1);
        let mut state = LeaseState::initial();
        let claim = LeaseEvent::claimed(active.clone(), 10, 20).expect("claim event");
        assert_eq!(claim.resulting_proof(), &active);
        assert_eq!(claim.observed_at(), 10);
        apply(&mut state, claim);
        apply(
            &mut state,
            LeaseEvent::heartbeat(active.clone(), 12, 25).expect("heartbeat event"),
        );
        apply(
            &mut state,
            LeaseEvent::effect_started(active.clone(), 13).expect("effect event"),
        );
        apply(
            &mut state,
            LeaseEvent::acknowledged(active.clone(), 30).expect("ack event"),
        );

        assert_eq!(state.phase(), LeasePhase::Acknowledged);
        assert_eq!(state.active_proof(), Some(&active));
        assert_eq!(state.issued_at(), Some(10));
        assert_eq!(state.last_heartbeat_at(), Some(12));
        assert_eq!(state.expires_at(), Some(25));
        assert_eq!(state.effect_started_at(), Some(13));
        assert_eq!(state.acknowledged_at(), Some(30));
        assert_eq!(state.last_observed_at(), Some(30));
    }

    #[test]
    fn release_requires_the_next_claim_generation() {
        let first = proof("worker-a", "lease-a", 1);
        let second = proof("worker-b", "lease-b", 2);
        let mut state = LeaseState::initial();
        apply(
            &mut state,
            LeaseEvent::claimed(first.clone(), 1, 10).expect("claim"),
        );
        apply(&mut state, LeaseEvent::released(first, 2).expect("release"));
        assert_eq!(state.phase(), LeasePhase::Available);
        assert_eq!(state.issued_at(), None);
        assert_eq!(state.last_heartbeat_at(), None);
        assert_eq!(state.last_observed_at(), Some(2));
        apply(
            &mut state,
            LeaseEvent::claimed(second.clone(), 3, 12).expect("next claim"),
        );
        assert_eq!(state.active_proof(), Some(&second));
        assert_eq!(state.issued_at(), Some(3));
        assert_eq!(state.last_heartbeat_at(), Some(3));
        assert_eq!(state.last_observed_at(), Some(3));
    }

    #[test]
    fn reclaim_at_expiry_records_exact_bounded_lineage() {
        let predecessor = proof("worker-a", "lease-a", 1);
        let successor = proof("worker-b", "lease-b", 2);
        let mut state = LeaseState::initial();
        apply(
            &mut state,
            LeaseEvent::claimed(predecessor.clone(), 10, 20).expect("claim"),
        );
        apply(
            &mut state,
            LeaseEvent::reclaimed(predecessor.clone(), 20, 20, successor.clone(), 30)
                .expect("reclaim"),
        );

        let lineage = state.last_reclaim().expect("reclaim lineage");
        assert_eq!(lineage.predecessor(), &predecessor);
        assert_eq!(lineage.predecessor_expires_at(), 20);
        assert_eq!(lineage.reclaimed_at(), 20);
        assert_eq!(lineage.successor(), &successor);
        assert_eq!(state.active_proof(), Some(&successor));
    }

    #[test]
    fn reclaim_before_expiry_or_with_wrong_expiry_is_rejected_atomically() {
        let predecessor = proof("worker-a", "lease-a", 1);
        let successor = proof("worker-b", "lease-b", 2);
        let mut state = LeaseState::initial();
        apply(
            &mut state,
            LeaseEvent::claimed(predecessor.clone(), 10, 20).expect("claim"),
        );
        assert!(LeaseEvent::reclaimed(predecessor.clone(), 20, 19, successor.clone(), 30).is_err());
        let wrong_expiry =
            LeaseEvent::reclaimed(predecessor, 19, 20, successor, 30).expect("well-formed event");
        assert_rejected_atomically(&mut state, &wrong_expiry);
    }

    #[test]
    fn reclaim_rejects_wrong_predecessor_identity_atomically() {
        let active = proof("worker-a", "lease-a", 1);
        let mut state = LeaseState::initial();
        apply(
            &mut state,
            LeaseEvent::claimed(active, 1, 5).expect("claim"),
        );

        for (predecessor, successor) in [
            (
                proof("worker-b", "lease-a", 1),
                proof("successor", "lease-b", 2),
            ),
            (
                proof("worker-a", "lease-other", 1),
                proof("successor", "lease-b", 2),
            ),
            (
                proof("worker-a", "lease-a", 2),
                proof("successor", "lease-b", 3),
            ),
        ] {
            let event = LeaseEvent::reclaimed(predecessor, 5, 5, successor, 10)
                .expect("well-formed reclaim");
            assert_rejected_atomically(&mut state, &event);
        }
    }

    #[test]
    fn consecutive_reclaims_advance_exactly_and_retain_latest_lineage() {
        let first = proof("worker-a", "lease-a", 1);
        let second = proof("worker-b", "lease-b", 2);
        let third = proof("worker-c", "lease-c", 3);
        let mut state = LeaseState::initial();
        apply(
            &mut state,
            LeaseEvent::claimed(first.clone(), 1, 5).expect("claim"),
        );
        apply(
            &mut state,
            LeaseEvent::reclaimed(first, 5, 5, second.clone(), 10).expect("first reclaim"),
        );
        apply(
            &mut state,
            LeaseEvent::reclaimed(second.clone(), 10, 10, third.clone(), 15)
                .expect("second reclaim"),
        );

        assert_eq!(state.generation(), 3);
        assert_eq!(state.active_proof(), Some(&third));
        let lineage = state.last_reclaim().expect("latest reclaim lineage");
        assert_eq!(lineage.predecessor(), &second);
        assert_eq!(lineage.predecessor_expires_at(), 10);
        assert_eq!(lineage.reclaimed_at(), 10);
        assert_eq!(lineage.successor(), &third);
    }

    #[test]
    fn every_bound_transition_rejects_wrong_worker_lease_or_generation() {
        let active = proof("worker-a", "lease-a", 1);
        let wrong = [
            proof("worker-b", "lease-a", 1),
            proof("worker-a", "lease-b", 1),
            proof("worker-a", "lease-a", 2),
        ];
        for presented in wrong {
            let mut state = LeaseState::initial();
            apply(
                &mut state,
                LeaseEvent::claimed(active.clone(), 1, 10).expect("claim"),
            );
            assert_rejected_atomically(
                &mut state,
                &LeaseEvent::heartbeat(presented.clone(), 2, 11).expect("heartbeat"),
            );
            assert_rejected_atomically(
                &mut state,
                &LeaseEvent::released(presented.clone(), 2).expect("release"),
            );
            assert_rejected_atomically(
                &mut state,
                &LeaseEvent::effect_started(presented, 2).expect("effect"),
            );
        }

        let mut fenced = LeaseState::initial();
        apply(
            &mut fenced,
            LeaseEvent::claimed(active.clone(), 1, 10).expect("claim"),
        );
        apply(
            &mut fenced,
            LeaseEvent::effect_started(active, 2).expect("effect"),
        );
        for presented in [
            proof("worker-b", "lease-a", 1),
            proof("worker-a", "lease-b", 1),
            proof("worker-a", "lease-a", 2),
        ] {
            assert_rejected_atomically(
                &mut fenced,
                &LeaseEvent::acknowledged(presented, 3).expect("ack"),
            );
        }
    }

    #[test]
    fn stale_predecessor_actions_fail_after_reclaim() {
        let predecessor = proof("worker-a", "lease-a", 1);
        let successor = proof("worker-b", "lease-b", 2);
        let mut state = LeaseState::initial();
        apply(
            &mut state,
            LeaseEvent::claimed(predecessor.clone(), 1, 5).expect("claim"),
        );
        apply(
            &mut state,
            LeaseEvent::reclaimed(predecessor.clone(), 5, 5, successor, 10).expect("reclaim"),
        );
        assert!(state
            .apply(&LeaseEvent::heartbeat(predecessor.clone(), 6, 11).expect("heartbeat"))
            .is_err());
        assert!(state
            .apply(&LeaseEvent::released(predecessor.clone(), 6).expect("release"))
            .is_err());
        assert!(state
            .apply(&LeaseEvent::effect_started(predecessor, 6).expect("effect"))
            .is_err());
    }

    #[test]
    fn durable_effect_fence_prevents_reclaim_release_and_double_effect() {
        let active = proof("worker-a", "lease-a", 1);
        let successor = proof("worker-b", "lease-b", 2);
        let mut state = LeaseState::initial();
        apply(
            &mut state,
            LeaseEvent::claimed(active.clone(), 1, 5).expect("claim"),
        );
        apply(
            &mut state,
            LeaseEvent::effect_started(active.clone(), 2).expect("effect"),
        );
        assert!(state
            .apply(&LeaseEvent::released(active.clone(), 3).expect("release"))
            .is_err());
        assert!(state
            .apply(&LeaseEvent::reclaimed(active.clone(), 5, 5, successor, 10).expect("reclaim"))
            .is_err());
        assert!(state
            .apply(&LeaseEvent::effect_started(active.clone(), 3).expect("effect"))
            .is_err());
        assert!(state
            .apply(&LeaseEvent::heartbeat(active, 3, 10).expect("heartbeat"))
            .is_err());
        assert_eq!(state.phase(), LeasePhase::EffectFenced);
    }

    #[test]
    fn acknowledgement_requires_fence_exact_proof_and_is_not_repeatable() {
        let active = proof("worker-a", "lease-a", 1);
        let mut state = LeaseState::initial();
        apply(
            &mut state,
            LeaseEvent::claimed(active.clone(), 1, 5).expect("claim"),
        );
        assert!(state
            .apply(&LeaseEvent::acknowledged(active.clone(), 2).expect("ack"))
            .is_err());
        apply(
            &mut state,
            LeaseEvent::effect_started(active.clone(), 2).expect("effect"),
        );
        assert!(state
            .apply(&LeaseEvent::acknowledged(proof("worker-b", "lease-a", 1), 3).expect("ack"))
            .is_err());
        apply(
            &mut state,
            LeaseEvent::acknowledged(active.clone(), 2).expect("equal-time ack"),
        );
        assert!(state
            .apply(&LeaseEvent::acknowledged(active, 3).expect("repeat ack"))
            .is_err());
    }

    #[test]
    fn skipped_generations_and_generation_overflow_are_rejected() {
        let mut initial = LeaseState::initial();
        assert!(initial
            .apply(&LeaseEvent::claimed(proof("worker-a", "lease-a", 2), 1, 5).expect("claim"))
            .is_err());

        let exhausted: LeaseState = serde_json::from_value(json!({
            "phase": "available",
            "lease": {
                "last_generation": u64::MAX,
                "last_observed_at": 10
            }
        }))
        .expect("valid exhausted state");
        let mut exhausted = exhausted;
        assert!(exhausted
            .apply(
                &LeaseEvent::claimed(proof("worker-a", "lease-a", u64::MAX), 11, 20)
                    .expect("claim event")
            )
            .is_err());

        let exhausted_active: LeaseState = serde_json::from_value(json!({
            "phase": "active",
            "lease": {
                "proof": {
                    "worker": "worker-a",
                    "lease_id": "lease-a",
                    "generation": u64::MAX
                },
                "issued_at": 1,
                "last_heartbeat_at": 1,
                "expires_at": 5
            }
        }))
        .expect("valid exhausted active state");
        assert_eq!(exhausted_active.generation(), u64::MAX);
        assert!(LeaseEvent::reclaimed(
            proof("worker-a", "lease-a", u64::MAX),
            5,
            5,
            proof("worker-b", "lease-b", u64::MAX),
            10,
        )
        .is_err());

        let predecessor = proof("worker-a", "lease-a", 1);
        let mut active = LeaseState::initial();
        apply(
            &mut active,
            LeaseEvent::claimed(predecessor.clone(), 1, 5).expect("claim"),
        );
        assert!(
            LeaseEvent::reclaimed(predecessor, 5, 5, proof("worker-b", "lease-b", 3), 10).is_err()
        );
    }

    #[test]
    fn timestamp_rollback_equality_expiry_and_shortening_rules_are_deterministic() {
        let active = proof("worker-a", "lease-a", 1);
        let mut state = LeaseState::initial();
        apply(
            &mut state,
            LeaseEvent::claimed(active.clone(), 10, 20).expect("claim"),
        );
        assert!(state
            .apply(&LeaseEvent::heartbeat(active.clone(), 10, 21).expect("heartbeat"))
            .is_err());
        assert!(state
            .apply(&LeaseEvent::heartbeat(active.clone(), 11, 19).expect("heartbeat"))
            .is_err());
        assert!(state
            .apply(&LeaseEvent::heartbeat(active.clone(), 20, 21).expect("heartbeat"))
            .is_err());
        apply(
            &mut state,
            LeaseEvent::heartbeat(active.clone(), 11, 20).expect("heartbeat"),
        );
        assert!(state
            .apply(&LeaseEvent::released(active.clone(), 11).expect("release"))
            .is_err());
        assert!(state
            .apply(&LeaseEvent::effect_started(active, 20).expect("effect"))
            .is_err());
    }

    #[test]
    fn serde_roundtrip_is_canonical_and_rejects_invalid_shapes_and_identifiers() {
        let event =
            LeaseEvent::claimed(proof("worker-a", "lease-a", 1), 10, 20).expect("claim event");
        let value = serde_json::to_value(&event).expect("serialize event");
        assert_eq!(value["event"], "claimed");
        assert_eq!(value["data"]["proof"]["worker"], "worker-a");
        assert_eq!(
            serde_json::from_value::<LeaseEvent>(value.clone()).expect("deserialize event"),
            event
        );

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .expect("event object")
            .insert("unknown".to_string(), Value::Bool(true));
        assert!(serde_json::from_value::<LeaseEvent>(unknown).is_err());

        let mut inner_unknown = value.clone();
        inner_unknown["data"]
            .as_object_mut()
            .expect("event data")
            .insert("unknown".to_string(), Value::Bool(true));
        assert!(serde_json::from_value::<LeaseEvent>(inner_unknown).is_err());

        let mut missing = value.clone();
        missing["data"]["proof"]
            .as_object_mut()
            .expect("proof object")
            .remove("worker");
        assert!(serde_json::from_value::<LeaseEvent>(missing).is_err());

        let mut oversized = value;
        oversized["data"]["proof"]["worker"] = Value::String("w".repeat(129));
        assert!(serde_json::from_value::<LeaseEvent>(oversized).is_err());
        assert!(WorkerIdentity::new("worker/unsafe").is_err());
        assert!(LeaseIdentity::new("..").is_err());
        assert!(WorkerIdentity::new("w".repeat(MAX_CANONICAL_ID_BYTES)).is_ok());
        assert!(WorkerIdentity::new("w".repeat(MAX_CANONICAL_ID_BYTES + 1)).is_err());

        let canonical = serde_json::to_string(&event).expect("serialize canonical event");
        assert_eq!(
            canonical,
            r#"{"event":"claimed","data":{"proof":{"worker":"worker-a","lease_id":"lease-a","generation":1},"observed_at":10,"expires_at":20}}"#
        );
        let decoded: LeaseEvent = serde_json::from_str(&canonical).expect("decode canonical event");
        assert_eq!(
            serde_json::to_string(&decoded).expect("reserialize canonical event"),
            canonical
        );

        let malformed_state = json!({
            "phase": "active",
            "lease": {
                "proof": {
                    "worker": "worker-a",
                    "lease_id": "lease-a",
                    "generation": 1
                },
                "issued_at": 10,
                "last_heartbeat_at": 9,
                "expires_at": 20
            }
        });
        assert!(serde_json::from_value::<LeaseState>(malformed_state).is_err());

        let state = LeaseState::replay([&event]).expect("replay canonical event");
        let state_json = serde_json::to_string(&state).expect("serialize canonical state");
        assert_eq!(
            state_json,
            r#"{"phase":"active","lease":{"proof":{"worker":"worker-a","lease_id":"lease-a","generation":1},"issued_at":10,"last_heartbeat_at":10,"expires_at":20}}"#
        );
        assert_eq!(
            serde_json::from_str::<LeaseState>(&state_json).expect("decode canonical state"),
            state
        );
    }

    #[test]
    fn replay_is_equivalent_and_repeated_skipped_or_reordered_events_fail() {
        let active = proof("worker-a", "lease-a", 1);
        let events = vec![
            LeaseEvent::claimed(active.clone(), 1, 10).expect("claim"),
            LeaseEvent::heartbeat(active.clone(), 2, 12).expect("heartbeat"),
            LeaseEvent::effect_started(active.clone(), 3).expect("effect"),
            LeaseEvent::acknowledged(active, 4).expect("ack"),
        ];
        let replayed = LeaseState::replay(&events).expect("replay");
        let mut incremental = LeaseState::initial();
        for event in &events {
            incremental.apply(event).expect("incremental apply");
        }
        assert_eq!(incremental, replayed);
        let serialized = serde_json::to_vec(&events).expect("serialize events");
        let decoded: Vec<LeaseEvent> = serde_json::from_slice(&serialized).expect("decode events");
        assert_eq!(
            LeaseState::replay(&decoded).expect("decoded replay"),
            replayed
        );

        let repeated = vec![events[0].clone(), events[0].clone()];
        assert!(LeaseState::replay(&repeated).is_err());
        let skipped = vec![events[2].clone()];
        assert!(LeaseState::replay(&skipped).is_err());
        let reordered = vec![events[0].clone(), events[2].clone(), events[1].clone()];
        assert!(LeaseState::replay(&reordered).is_err());

        let mut reordered_incremental = LeaseState::initial();
        reordered_incremental
            .apply(&events[0])
            .expect("ordered claim");
        reordered_incremental
            .apply(&events[2])
            .expect("effect start before stale heartbeat");
        assert_rejected_atomically(&mut reordered_incremental, &events[1]);
    }
}
