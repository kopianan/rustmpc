//! # High-level threshold signing protocol implementation
//!
//! Key feature of GG20 protocol is one-round online signing, meaning that every party needs to
//! broadcast just a single message to sign a data. However, it still requires completing an offline
//! computation for fixed set of parties
//!
//! ## How to get things work
//!
//! First of all, parties need to carry out distributed key generation protocol (see [keygen module]).
//! After DKG is successfully completed, it outputs [LocalKey] — a party local secret share.
//! Then you fix a set of parties who will participate in threshold signing, and they run
//! [OfflineStage] protocol. `OfflineStage` implements [StateMachine] and can be executed in the same
//! way as [Keygen]. `OfflineStage` outputs a [completedOfflineStage]. [SignManual] takes a
//! `CompletedOfflineStagE` and allows you to perform one-round signing. It doesn't implement
//! `StateMachine`, but rather provides methods to construct messages and final signature manually
//! (refer to [SignManual] documentation to see how to use it).
//!
//! [keygen module]: super::keygen
//! [Keygen]: super::keygen::Keygen
//! [LocalKey]: super::keygen::LocalKey
//! [StateMachine]: round_based::StateMachine

use std::mem::replace;
use std::time::Duration;
use sha2::Sha256;

use round_based::containers::{push::Push, BroadcastMsgs, MessageStore, P2PMsgs, Store, StoreErr};
use round_based::{IsCritical, Msg, StateMachine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::utilities::mta::MessageA;

use curv::{
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Scalar}, BigInt
};

use crate::common::party_i::{
    Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2,
    SignBroadcastPhase1, SignDecommitPhase1, LocalKeyShare,
};

//mod fmt;
use crate::signing::rounds::*;
pub use crate::signing::rounds::{CompletedOfflineStage, Error as ProceedError};

/// Offline Stage of GG20 signing
///
/// Successfully carried out Offline Stage will produce [CompletedOfflineStagE] that can
/// be used for one-round signing multiple times.
pub struct OfflineStage {
    round: OfflineR,

    msgs1: Option<Store<BroadcastMsgs<u16>>>,
    msgs2: Option<Store<BroadcastMsgs<(MessageA, SignBroadcastPhase1)>>>,
    msgs3: Option<Store<P2PMsgs<(GammaI, WI)>>>,
    msgs4: Option<Store<BroadcastMsgs<DeltaI>>>,
    msgs5: Option<Store<BroadcastMsgs<SignDecommitPhase1>>>,
    msgs6: Option<Store<BroadcastMsgs<(Phase5Com1,
                                       Phase5ADecom1,
                                       HomoELGamalProof<Secp256k1, Sha256>,
                                       DLogProof<Secp256k1, Sha256>)>>>,
    msgs7: Option<Store<BroadcastMsgs<(Phase5Com2, Phase5DDecom2)>>>,
    msgs8: Option<Store<BroadcastMsgs<Scalar<Secp256k1>>>>,

    msgs_queue: MsgQueue,

    party_i: u16,
    party_n: u16,
}

impl OfflineStage {
    /// Construct a party of offline stage of threshold signing protocol
    ///
    /// Once offline stage is finished, parties can do one-round threshold signing (i.e. they only
    /// need to exchange a single set of messages).
    ///
    /// Takes party index `i` (in range `[1; n]`), list `s_l` of parties' indexes from keygen protocol
    /// (`s_l[i]` must be an index of party `i` that was used by this party in keygen protocol), and
    /// party local secret share `local_key`.
    ///
    /// Returns error if given arguments are contradicting.
    pub fn new(party_num_int: u16, threshold: u16, local_key_share: LocalKeyShare, message_bn: BigInt) -> Result<Self> {
        
        Ok(Self {
            round: OfflineR::R0(Round0 { party_num_int, threshold, local_key_share, message_bn }),

            msgs1: Some(Round1::expects_messages(party_num_int, threshold+1)),
            msgs2: Some(Round2::expects_messages(party_num_int, threshold+1)),
            msgs3: Some(Round3::expects_messages(party_num_int, threshold+1)),
            msgs4: Some(Round4::expects_messages(party_num_int, threshold+1)),
            msgs5: Some(Round5::expects_messages(party_num_int, threshold+1)),
            msgs6: Some(Round6::expects_messages(party_num_int, threshold+1)),
            msgs7: Some(Round7::expects_messages(party_num_int, threshold+1)),
            msgs8: Some(Round8::expects_messages(party_num_int, threshold+1)),

            msgs_queue: MsgQueue(vec![]),

            party_i: party_num_int,
            party_n: threshold+1,
        })
    }

    // fn proceed_state(&mut self, may_block: bool) -> Result<()> {
    //     self.proceed_round(may_block)?;
    //     self.proceed_decommit_round(may_block)
    // }

    fn proceed_round(&mut self, may_block: bool) -> Result<()> {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store5_wants_more = self.msgs5.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store6_wants_more = self.msgs6.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store7_wants_more = self.msgs7.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store8_wants_more = self.msgs8.as_ref().map(|s| s.wants_more()).unwrap_or(false);


        let next_state: OfflineR;
        let try_again: bool = match replace(&mut self.round, OfflineR::Gone) {
            OfflineR::R0(round) if !round.is_expensive() || may_block => {
                next_state = round
                    .proceed(&mut self.msgs_queue)
                    .map(OfflineR::R1)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ OfflineR::R0(_) => {
                next_state = s;
                false
            }
            OfflineR::R1(round) if !store1_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs1.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R2)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ OfflineR::R1(_) => {
                next_state = s;
                false
            }
            OfflineR::R2(round) if !store2_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs2.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R3)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ OfflineR::R2(_) => {
                next_state = s;
                false
            }
            OfflineR::R3(round) if !store3_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs3.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R4)
                    .map_err(Error::ProceedRound)?;
                true
            }
            s @ OfflineR::R3(_) => {
                next_state = s;
                false
            }
            OfflineR::R4(round) if !store4_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs4.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R5)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ OfflineR::R4(_) => {
                next_state = s;
                false
            }
            OfflineR::R5(round) if !store5_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs5.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R6)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ OfflineR::R5(_) => {
                next_state = s;
                false
            }
            OfflineR::R6(round) if !store6_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs6.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R7)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ OfflineR::R6(_) => {
                next_state = s;
                false
            }
            OfflineR::R7(round) if !store7_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs7.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs, &mut self.msgs_queue)
                    .map(OfflineR::R8)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ OfflineR::R7(_) => {
                next_state = s;
                false
            }
            OfflineR::R8(round) if !store8_wants_more && (!round.is_expensive() || may_block) => {
                let store = self.msgs8.take().ok_or(InternalError::StoreGone)?;
                let msgs = store
                    .finish()
                    .map_err(InternalError::RetrieveMessagesFromStore)?;
                next_state = round
                    .proceed(msgs)
                    .map(OfflineR::Finished)
                    .map_err(Error::ProceedRound)?;
                false
            }
            s @ OfflineR::R8(_) => {
                next_state = s;
                false
            }
            s @ OfflineR::Finished(_) | s @ OfflineR::Gone => {
                next_state = s;
                false
            }
        };

        self.round = next_state;
        if try_again {
            self.proceed_round(may_block)
        } else {
            Ok(())
        }
    }
}

impl StateMachine for OfflineStage {
    type MessageBody = OfflineProtocolMessage;
    type Err = Error;
    type Output = CompletedOfflineStage;

    fn handle_incoming(&mut self, msg: Msg<Self::MessageBody>) -> Result<(), Self::Err> {
        let current_round = self.current_round();

        match msg.body {
            OfflineProtocolMessage(OfflineM::M1(m)) => {
                let store = self
                    .msgs1
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 1,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M2(m)) => {
                let store = self
                    .msgs2
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M3(m)) => {
                let store = self
                    .msgs3
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M4(m)) => {
                let store = self
                    .msgs4
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M5(m)) => {
                let store = self
                    .msgs5
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M6(m)) => {
                let store = self
                    .msgs6
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M7(m)) => {
                let store = self
                    .msgs7
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
            OfflineProtocolMessage(OfflineM::M8(m)) => {
                let store = self
                    .msgs8
                    .as_mut()
                    .ok_or(Error::ReceivedOutOfOrderMessage {
                        current_round,
                        msg_round: 2,
                    })?;
                store
                    .push_msg(Msg {
                        sender: msg.sender,
                        receiver: msg.receiver,
                        body: m,
                    })
                    .map_err(Error::HandleMessage)?;
            }
        }
        self.proceed_round(false)
    }

    fn message_queue(&mut self) -> &mut Vec<Msg<Self::MessageBody>> {
        &mut self.msgs_queue.0
    }

    fn wants_to_proceed(&self) -> bool {
        let store1_wants_more = self.msgs1.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store2_wants_more = self.msgs2.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store3_wants_more = self.msgs3.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store4_wants_more = self.msgs4.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store5_wants_more = self.msgs5.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store6_wants_more = self.msgs6.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store7_wants_more = self.msgs7.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        let store8_wants_more = self.msgs8.as_ref().map(|s| s.wants_more()).unwrap_or(false);
        
        match &self.round {
            OfflineR::R0(_) => true,
            OfflineR::R1(_) => !store1_wants_more,
            OfflineR::R2(_) => !store2_wants_more,
            OfflineR::R3(_) => !store3_wants_more,
            OfflineR::R4(_) => !store4_wants_more,
            OfflineR::R5(_) => !store5_wants_more,
            OfflineR::R6(_) => !store6_wants_more,
            OfflineR::R7(_) => !store7_wants_more,
            OfflineR::R8(_) => !store8_wants_more,
            OfflineR::Finished(_) | OfflineR::Gone => false,
        }
    }

    fn proceed(&mut self) -> Result<(), Self::Err> {
        self.proceed_round(true)
    }

    fn round_timeout(&self) -> Option<Duration> {
        None
    }

    fn round_timeout_reached(&mut self) -> Self::Err {
        panic!("no timeout was set")
    }

    fn is_finished(&self) -> bool {
        matches!(&self.round, OfflineR::Finished(_))
    }

    fn pick_output(&mut self) -> Option<Result<Self::Output, Self::Err>> {
        match self.round {
            OfflineR::Finished(_) => (),
            OfflineR::Gone => return Some(Err(Error::DoublePickOutput)),
            _ => return None,
        }

        match replace(&mut self.round, OfflineR::Gone) {
            OfflineR::Finished(result) => Some(Ok(result)),
            _ => unreachable!("guaranteed by match expression above"),
        }
    }

    fn current_round(&self) -> u16 {
        match &self.round {
            OfflineR::R0(_) => 0,
            OfflineR::R1(_) => 1,
            OfflineR::R2(_) => 2,
            OfflineR::R3(_) => 3,
            OfflineR::R4(_) => 4,
            OfflineR::R5(_) => 5,
            OfflineR::R6(_) => 6,
            OfflineR::R7(_) => 7,
            OfflineR::R8(_) => 8,
            OfflineR::Finished(_) | OfflineR::Gone => 9,
        }
    }

    fn total_rounds(&self) -> Option<u16> {
        Some(8)
    }

    fn party_ind(&self) -> u16 {
        self.party_i
    }

    fn parties(&self) -> u16 {
        self.party_n
    }
}

impl crate::dkg::traits::RoundBlame for OfflineStage {
    /// RoundBlame returns number of unwilling parties and a vector of their party indexes.
    fn round_blame(&self) -> (u16, Vec<u16>) {
        let store1_blame = self.msgs1.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store2_blame = self.msgs2.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store3_blame = self.msgs3.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store4_blame = self.msgs4.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store5_blame = self.msgs5.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store6_blame = self.msgs6.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store7_blame = self.msgs7.as_ref().map(|s| s.blame()).unwrap_or_default();
        let store8_blame = self.msgs8.as_ref().map(|s| s.blame()).unwrap_or_default();

        let default = (0, vec![]);
        match &self.round {
            OfflineR::R0(_) => default,
            OfflineR::R1(_) => store1_blame,
            OfflineR::R2(_) => store2_blame,
            OfflineR::R3(_) => store3_blame,
            OfflineR::R4(_) => store4_blame,
            OfflineR::R5(_) => store5_blame,
            OfflineR::R6(_) => store6_blame,
            OfflineR::R7(_) => store7_blame,
            OfflineR::R8(_) => store8_blame,
            OfflineR::Finished(_) => store8_blame,
            OfflineR::Gone => default,
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum OfflineR {
    R0(Round0),
    R1(Round1),
    R2(Round2),
    R3(Round3),
    R4(Round4),
    R5(Round5),
    R6(Round6),
    R7(Round7),
    R8(Round8),
    Finished(CompletedOfflineStage),
    Gone,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OfflineProtocolMessage(OfflineM);

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(clippy::large_enum_variant)]
enum OfflineM {
    M1(u16),
    M2((MessageA, SignBroadcastPhase1)),
    M3((GammaI, WI)),
    M4(DeltaI),
    M5(SignDecommitPhase1),
    M6((Phase5Com1,
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>)),
    M7((Phase5Com2, Phase5DDecom2)),
    M8(Scalar<Secp256k1>),
}

struct MsgQueue(Vec<Msg<OfflineProtocolMessage>>);

macro_rules! make_pushable {
    ($($constructor:ident $t:ty),*$(,)?) => {
        $(
        impl Push<Msg<$t>> for MsgQueue {
            fn push(&mut self, m: Msg<$t>) {
                Vec::push(&mut self.0, Msg{
                    sender: m.sender,
                    receiver: m.receiver,
                    body: OfflineProtocolMessage(OfflineM::$constructor(m.body))
                })
            }
        }
        )*
    };
}

make_pushable! {
    M1 u16,
    M2 (MessageA, SignBroadcastPhase1),
    M3 (GammaI, WI),
    M4 DeltaI,
    M5 SignDecommitPhase1,
    M6 (Phase5Com1,
        Phase5ADecom1,
        HomoELGamalProof<Secp256k1, Sha256>,
        DLogProof<Secp256k1, Sha256>),
    M7 (Phase5Com2, Phase5DDecom2),
    M8 Scalar<Secp256k1>,
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    /// Too few parties (`n < 2`)
    #[error("at least 2 parties are required for signing")]
    TooFewParties,
    /// Too many parties. `n` must fit into `u16`, so only `n < u16::MAX` values are supported.
    #[error("too many parties: n={n}, n must be less than 2^16")]
    TooManyParties { n: usize },
    /// Party index `i` is not in range `[1; n]`
    #[error("party index is not in range [1; n]")]
    InvalidPartyIndex,
    /// List `s_l` is invalid. Either it contains duplicates (`exist i j. i != j && s_l[i] = s_l[j]`),
    /// or contains index that is not in the range `[1; keygen_n]`, `keygen_n` — number of parties
    /// participated in DKG (`exist i. s_l[i] = 0 || s_l[i] > keygen_n`).
    #[error("invalid s_l")]
    InvalidSl,

    /// Round proceeding resulted in protocol error
    #[error("proceeding round: {0}")]
    ProceedRound(crate::signing::rounds::Error),

    /// Received message which we didn't expect to receive now (e.g. message from previous round)
    #[error(
        "didn't expect to receive message from round {msg_round} (being at round {current_round})"
    )]
    ReceivedOutOfOrderMessage { current_round: u16, msg_round: u16 },
    /// Received message didn't pass pre-validation
    #[error("received message didn't pass pre-validation: {0}")]
    HandleMessage(#[source] StoreErr),

    /// [OfflineStage::pick_output] called twice
    #[error("pick_output called twice")]
    DoublePickOutput,

    /// A bug in protocol implementation
    #[error("offline stage protocol bug: {0}")]
    Bug(InternalError),
}

#[derive(Debug, Error)]
pub enum InternalError {
    #[error("store gone")]
    StoreGone,
    #[error("store reported that it's collected all the messages it needed, but refused to give received messages")]
    RetrieveMessagesFromStore(StoreErr),
    #[error("decommit round expected to be in NotStarted state")]
    DecommitRoundWasntInInitialState,
}

impl From<InternalError> for Error {
    fn from(err: InternalError) -> Self {
        Error::Bug(err)
    }
}

impl IsCritical for Error {
    fn is_critical(&self) -> bool {
        match self {
            Error::TooFewParties => true,
            Error::TooManyParties { .. } => true,
            Error::InvalidPartyIndex => true,
            Error::InvalidSl => true,
            Error::ProceedRound(_) => true,
            Error::ReceivedOutOfOrderMessage { .. } => false,
            Error::HandleMessage(_) => false,
            Error::DoublePickOutput => true,
            Error::Bug(_) => true,
        }
    }
}

/// Manual GG20 signing
///
/// After you completed [OfflineStage] and got [CompletedOfflineStagE], parties can perform signing
/// simply by broadcasting a single message.
///
/// ## Example
/// ```no_run
/// # use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::{
/// #     state_machine::sign::{CompletedOfflineStagE, SignManual, PartialSignature},
/// #     party_i::{LocalSignature, verify},
/// # };
/// # use curv::arithmetic::{BigInt, Converter};
/// # type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
/// # fn broadcast(msg: PartialSignature) -> Result<()> { panic!() }
/// # fn wait_messages() -> Result<Vec<PartialSignature>> { panic!() }
/// # fn main() -> Result<()> {
/// # let completed_offline_stage: CompletedOfflineStagE = panic!();
/// let data = BigInt::from_bytes(b"a message");
///
/// // Sign a message locally
/// let (sign, msg) = SignManual::new(data.clone(), completed_offline_stage)?;
/// // Broadcast local partial signature
/// broadcast(msg)?;
/// // Collect partial signatures from other parties
/// let sigs: Vec<PartialSignature> = wait_messages()?;
/// // Complete signing
/// let signature = sign.complete(&sigs)?;
/// // Verify that signature matches joint public key
/// assert!(verify(&signature, completed_offline_stage.public_key(), &data).is_ok());
/// # Ok(())
/// # }
/// ```
/// 
/*
#[derive(Clone)]
pub struct SignManual {
    state: Round7,
}

impl SignManual {
    pub fn new(
        message: BigInt,
        completed_offline_stage: CompletedOfflineStage,
    ) -> Result<(Self, PartialSignature), SignError> {
        Round7::new(&message, completed_offline_stage)
            .map(|(state, m)| (Self { state }, m))
            .map_err(SignError::LocalSigning)
    }

    /// `sigs` must not include partial signature produced by local party (only partial signatures produced
    /// by other parties)
    pub fn complete(self, sigs: &[PartialSignature]) -> Result<SignatureRecid, SignError> {
        self.state
            .proceed_manual(sigs)
            .map_err(SignError::CompleteSigning)
    }
}
*/

#[derive(Debug, Error)]
pub enum SignError {
    #[error("signing message locally: {0}")]
    LocalSigning(crate::signing::rounds::Error),
    #[error("couldn't complete signing: {0}")]
    CompleteSigning(crate::signing::rounds::Error),
}
