#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

//use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
//use curv::BigInt;
use sha2::Sha256;

use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::Msg;

use crate::utilities::mta::{MessageA, MessageB};
use crate::common::ErrorType;

use curv::{
    cryptographic_primitives::{
        proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof,
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar},
    BigInt,
};

use crate::common::party_i::{
    Keys, LocalSignature, PartyPrivate, Phase5ADecom1, Phase5Com1, Phase5Com2, Phase5DDecom2,
    SharedKeys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SignatureRecid, //check_sig,
    LocalKeyShare,
};

use paillier::EncryptionKey;


type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub struct GWI(pub Point<Secp256k1>);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GammaI(pub MessageB);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WI(pub MessageB);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeltaI(Scalar<Secp256k1>);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RDash(Point<Secp256k1>);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SI(pub Point<Secp256k1>);
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HEGProof(pub HomoELGamalProof<Secp256k1, Sha256>);

pub struct Round0 {
    pub party_num_int: u16,
    pub threshold: u16,
    /// Party local secret share
    pub local_key_share: LocalKeyShare,
    pub message_bn: BigInt,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<u16>>,
    {
        let pk = self.local_key_share.party_keys;
        let sk = self.local_key_share.shared_keys;
        let pi = self.local_key_share.party_id - 1;
        let vss = self.local_key_share.vss_scheme_vec;
        let pai_k = self.local_key_share.paillier_key_vector;
        let ys = self.local_key_share.y_sum;

        output.push(Msg {
            sender: self.party_num_int,
            receiver: None,
            body: pi.clone(),
        });

        let round1 = Round1 {
            party_num_int: self.party_num_int,
            threshold: self.threshold,
            message_bn: self.message_bn,
            party_keys: pk,
            shared_keys: sk,
            party_id: pi,
            vss_scheme_vec: vss,
            paillier_key_vector: pai_k,
            y_sum: ys,
        };

        Ok(round1)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    party_num_int: u16,
    threshold: u16,
    message_bn: BigInt,
    party_keys: Keys,
    shared_keys: SharedKeys,
    party_id: u16,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    paillier_key_vector: Vec<EncryptionKey>,
    y_sum: Point<Secp256k1>,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<u16>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<(MessageA, SignBroadcastPhase1)>>,
    {
        let signers_vec: Vec<_> = input.into_vec_including_me(self.party_id.clone());
        let private = PartyPrivate::set_private(self.party_keys.clone(), self.shared_keys);
        println!("signers_vec = {:?}", signers_vec);//erwin_debug
        let sign_keys = SignKeys::create(
            &private,
            &self.vss_scheme_vec[usize::from(signers_vec[usize::from(self.party_num_int - 1)])],
            signers_vec[usize::from(self.party_num_int - 1)],       
            &signers_vec,
        );
        //////////////////////////////////////////////////////////////////////////////
        let (phase1_com, phase1_decom) = sign_keys.phase1_broadcast();
        let (m_a_k, _) = MessageA::a(&sign_keys.k_i, &self.party_keys.ek, &[]);

        output.push(Msg {
            sender: self.party_num_int,
            receiver: None,
            body: (m_a_k, phase1_com.clone()),
        });

        Ok(Round2 {
            party_num_int: self.party_num_int,
            threshold: self.threshold,
            message_bn: self.message_bn,
            party_keys: self.party_keys,
            vss_scheme_vec: self.vss_scheme_vec,
            paillier_key_vector: self.paillier_key_vector,
            y_sum: self.y_sum,
            phase1_com,
            signers_vec,
            sign_keys,
            phase1_decom,
        })
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<BroadcastMsgs<u16>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round2 {
    party_num_int: u16,
    threshold: u16,
    message_bn: BigInt,
    party_keys: Keys,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    paillier_key_vector: Vec<EncryptionKey>,
    y_sum: Point<Secp256k1>,
    phase1_com: SignBroadcastPhase1,
    signers_vec: Vec<u16>,
    sign_keys: SignKeys,
    phase1_decom: SignDecommitPhase1,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<(MessageA, SignBroadcastPhase1)>,
        mut output: O,
    ) -> Result<Round3>
    where
        O: Push<Msg<(GammaI, WI)>>,
    {
        let (m_a_vec, bc_vec): (Vec<_>, Vec<_>) = input
            .into_vec()
            .into_iter()
            .unzip();

        //bc_vec.push(self.phase1_com.clone());
        //assert_eq!(self.signers_vec.len(), bc_vec.len());

        //println!("m_a_vec = {:?}", m_a_vec);//erwin_debug
        //println!("bc_vec = {:?}", bc_vec);//erwin_debug
        //////////////////////////////////////////////////////////////////////////////
        let mut m_b_gamma_send_vec: Vec<MessageB> = Vec::new();
        let mut beta_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut m_b_w_send_vec: Vec<MessageB> = Vec::new();
        let mut ni_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        
        let mut j = 0;
        for i in 1..self.threshold + 2 {
            if i != self.party_num_int {
                let (m_b_gamma, beta_gamma, _, _) = MessageB::b(
                    &self.sign_keys.gamma_i,
                    &self.paillier_key_vector[usize::from(self.signers_vec[usize::from(i - 1)])],
                    m_a_vec[j].clone(),
                    &[],
                )
                .unwrap();
                let (m_b_w, beta_wi, _, _) = MessageB::b(
                    &self.sign_keys.w_i,
                    &self.paillier_key_vector[usize::from(self.signers_vec[usize::from(i - 1)])],
                    m_a_vec[j].clone(),
                    &[],
                )
                .unwrap();
                m_b_gamma_send_vec.push(m_b_gamma);
                m_b_w_send_vec.push(m_b_w);
                beta_vec.push(beta_gamma);
                ni_vec.push(beta_wi);
                j += 1;
            }
        }
        
        /*
        let party_indices = (1..=self.signers_vec.len())
            .map(|k| u16::try_from(k).unwrap())
            .filter(|&k| k != self.party_num_int);

        for ((j, gamma_i), w_i) in party_indices.zip(m_b_gamma_send_vec).zip(m_b_w_send_vec) {
            output.push(Msg {
                sender: self.party_num_int,
                receiver: Some(j),
                body: (GammaI(gamma_i.clone()), WI(w_i.clone())),
            });
        }*/

        let mut j = 0;
        for i in 1..self.threshold + 2 {
            if i != self.party_num_int {
                //println!("j = {}\n, m_b_gamma_send_vec[j] = {:?}\n, m_b_w_send_vec[j] = {:?}\n\n", j, m_b_gamma_send_vec[j], m_b_w_send_vec[j]);
                output.push(Msg {
                    sender: self.party_num_int,
                    receiver: Some(i),
                    body: (GammaI(m_b_gamma_send_vec[j].clone()), WI(m_b_w_send_vec[j].clone())),
                });
                j += 1;
            }
        }

        Ok(Round3 {
            party_num_int: self.party_num_int,
            threshold: self.threshold,
            message_bn: self.message_bn,
            party_keys: self.party_keys,
            vss_scheme_vec: self.vss_scheme_vec,
            y_sum: self.y_sum,
            signers_vec: self.signers_vec,
            sign_keys: self.sign_keys,
            phase1_decom: self.phase1_decom,
            beta_vec,
            ni_vec,
            bc_vec,
        })
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<BroadcastMsgs<(MessageA, SignBroadcastPhase1)>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round3 {
    party_num_int: u16,
    threshold: u16,
    message_bn: BigInt,
    party_keys: Keys,
    vss_scheme_vec: Vec<VerifiableSS<Secp256k1>>,
    y_sum: Point<Secp256k1>,
    signers_vec: Vec<u16>,
    sign_keys: SignKeys,
    phase1_decom: SignDecommitPhase1,
    beta_vec: Vec<Scalar<Secp256k1>>,
    ni_vec: Vec<Scalar<Secp256k1>>,
    bc_vec: Vec<SignBroadcastPhase1>,
}

impl Round3 {
    pub fn proceed<O>(self, input_p2p: P2PMsgs<(GammaI, WI)>, mut output: O) -> Result<Round4>
    where
        O: Push<Msg<DeltaI>>, // TODO: unify TI and TIProof
    {
        let (m_b_gamma_rec_vec, m_b_w_rec_vec): (Vec<_>, Vec<_>) = input_p2p
            .into_vec()
            .into_iter()
            .map(|(gamma_i, w_i)| (gamma_i.0, w_i.0))
            .unzip();

        let mut alpha_vec: Vec<Scalar<Secp256k1>> = Vec::new();
        let mut miu_vec: Vec<Scalar<Secp256k1>> = Vec::new();
    
        let mut j = 0;
        let xi_com_vec = Keys::get_commitments_to_xi(&self.vss_scheme_vec);

        for i in 1..self.threshold + 2 {
            if i != self.party_num_int {
                let m_b = m_b_gamma_rec_vec[j].clone();
    
                let alpha_ij_gamma = m_b
                    .verify_proofs_get_alpha(&self.party_keys.dk, &self.sign_keys.k_i)
                    .expect("wrong dlog or m_b");
                let m_b = m_b_w_rec_vec[j].clone();
                let alpha_ij_wi = m_b
                    .verify_proofs_get_alpha(&self.party_keys.dk, &self.sign_keys.k_i)
                    .expect("wrong dlog or m_b");
                alpha_vec.push(alpha_ij_gamma.0);
                miu_vec.push(alpha_ij_wi.0);
                let g_w_i = Keys::update_commitments_to_xi(
                    &xi_com_vec[usize::from(self.signers_vec[usize::from(i - 1)])],
                    &self.vss_scheme_vec[usize::from(self.signers_vec[usize::from(i - 1)])],
                    self.signers_vec[usize::from(i - 1)],
                    &self.signers_vec,
                );
                assert_eq!(m_b.b_proof.pk, g_w_i);
                j += 1;
            }
        }
        //////////////////////////////////////////////////////////////////////////////
        let delta_i = self.sign_keys.phase2_delta_i(&alpha_vec, &self.beta_vec);
        let sigma = self.sign_keys.phase2_sigma_i(&miu_vec, &self.ni_vec);

        output.push(Msg {
            sender: self.party_num_int,
            receiver: None,
            body: DeltaI(delta_i.clone()),
        });

        Ok(Round4 {
            party_num_int: self.party_num_int,
            threshold: self.threshold,
            message_bn: self.message_bn,
            y_sum: self.y_sum,
            sign_keys: self.sign_keys,
            phase1_decom: self.phase1_decom,
            bc_vec: self.bc_vec,
            delta_i,
            m_b_gamma_rec_vec,
            sigma,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<(GammaI, WI)>> {
        containers::P2PMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round4 {
    party_num_int: u16,
    threshold: u16,
    message_bn: BigInt,
    y_sum: Point<Secp256k1>,
    sign_keys: SignKeys,
    phase1_decom: SignDecommitPhase1,
    bc_vec: Vec<SignBroadcastPhase1>,
    delta_i: Scalar<Secp256k1>,
    m_b_gamma_rec_vec: Vec<MessageB>,
    sigma: Scalar<Secp256k1>,
}

impl Round4 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<DeltaI>,
        mut output: O,
    ) -> Result<Round5>
    where
        O: Push<Msg<SignDecommitPhase1>>,
    {
        let  delta_vec = input.into_vec_including_me( DeltaI(self.delta_i) ).into_iter().map(|x| x.0).my_unzip();

        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);


        output.push(Msg {
            sender: self.party_num_int,
            receiver: None,
            body: self.phase1_decom.clone(),
        });

        Ok(Round5 {
            party_num_int: self.party_num_int,
            threshold: self.threshold,
            message_bn: self.message_bn,
            y_sum: self.y_sum,
            sign_keys: self.sign_keys,
            phase1_decom: self.phase1_decom,
            bc_vec: self.bc_vec,
            m_b_gamma_rec_vec: self.m_b_gamma_rec_vec,
            sigma: self.sigma,
            delta_inv,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<DeltaI>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round5 {
    party_num_int: u16,
    threshold: u16,
    message_bn: BigInt,
    y_sum: Point<Secp256k1>,
    sign_keys: SignKeys,
    phase1_decom: SignDecommitPhase1,
    bc_vec: Vec<SignBroadcastPhase1>,
    m_b_gamma_rec_vec: Vec<MessageB>,
    sigma: Scalar<Secp256k1>,
    delta_inv: Scalar<Secp256k1>,
}

impl Round5 {
    pub fn proceed<O>(
        self,
        decommit_round1: BroadcastMsgs<SignDecommitPhase1>,
        mut output: O,
    ) -> Result<Round6>
    where
        O: Push<Msg<(Phase5Com1,
                     Phase5ADecom1,
                     HomoELGamalProof<Secp256k1, Sha256>,
                     DLogProof<Secp256k1, Sha256>)>>,
    {
        let decom_vec: Vec<_> = decommit_round1.into_vec();
        //println!("decom_vec = {:?}\n", decom_vec);//erwin_debug
        let decomm_i = self.phase1_decom.clone();
        let bc_vec_self = self.bc_vec.clone();

        let b_proof_vec = (0..self.m_b_gamma_rec_vec.len())
            .map(|i| &self.m_b_gamma_rec_vec[i].b_proof)
            .collect::<Vec<&DLogProof<Secp256k1, Sha256>>>();

        let R = SignKeys::phase4(&self.delta_inv, &b_proof_vec, decom_vec, &bc_vec_self)
            .expect("bad gamma_i decommit");

        // adding local g_gamma_i
        let R = R + decomm_i.g_gamma_i * self.delta_inv;

        let local_sig =
            LocalSignature::phase5_local_sig(&self.sign_keys.k_i, 
                &self.message_bn, &R, &self.sigma, &self.y_sum);

        let (phase5_com, phase_5a_decom, helgamal_proof, dlog_proof_rho) =
            local_sig.phase5a_broadcast_5b_zkproof();

        output.push(Msg {
            sender: self.party_num_int,
            receiver: None,
            body: (phase5_com.clone(), 
                   phase_5a_decom.clone(), 
                   helgamal_proof.clone(), 
                   dlog_proof_rho.clone()),
        });

        Ok(Round6 {
            party_num_int: self.party_num_int,
            threshold: self.threshold,
            y_sum: self.y_sum,
            phase5_com,
            phase_5a_decom,
            helgamal_proof,
            dlog_proof_rho,
            R,
            local_sig,
            message_bn: self.message_bn,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<SignDecommitPhase1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round6 {
    party_num_int: u16,
    threshold: u16,
    y_sum: Point<Secp256k1>,
    phase5_com: Phase5Com1,
    phase_5a_decom: Phase5ADecom1,
    helgamal_proof: HomoELGamalProof<Secp256k1, Sha256>,
    dlog_proof_rho: DLogProof<Secp256k1, Sha256>,
    R: Point<Secp256k1>,
    local_sig: LocalSignature, 
    message_bn: BigInt,
}

impl Round6 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<(Phase5Com1,
                              Phase5ADecom1,
                              HomoELGamalProof<Secp256k1, Sha256>,
                              DLogProof<Secp256k1, Sha256>)>,
        mut output: O,
    ) -> Result<Round7>
    where
        O: Push<Msg<(Phase5Com2, Phase5DDecom2)>>,
    {
        let vi = self.phase_5a_decom.clone().V_i;
        
        let (commit5a_vec, phase_5a_decomm_vec, phase_5a_elgamal_vec, phase_5a_dlog_vec) = input
            .into_vec()
            /*
            .into_vec_including_me((
                self.phase5_com,
                self.phase_5a_decom,
                self.helgamal_proof,
                self.dlog_proof_rho),
            )
            */
            .into_iter()
            .unzip4();
        
        let (phase5_com2, phase_5d_decom2) = self.local_sig
            .phase5c(
                &phase_5a_decomm_vec,
                &commit5a_vec,
                &phase_5a_elgamal_vec,
                &phase_5a_dlog_vec,
                &vi,
                &self.R,
            )
            .expect("error phase5");

        output.push(Msg {
            sender: self.party_num_int,
            receiver: None,
            body: (phase5_com2.clone(), 
                   phase_5d_decom2.clone()),
        });
        
        //phase_5a_decomm_vec_includes_i
        let mut phase_5a_decomm_vec_includes_i = phase_5a_decomm_vec.clone();
        phase_5a_decomm_vec_includes_i.push(self.phase_5a_decom);

        Ok(Round7 {
            party_num_int: self.party_num_int,
            y_sum: self.y_sum,
            local_sig: self.local_sig, 
            message_bn: self.message_bn,
            phase5_com2,
            phase_5d_decom2,
            phase_5a_decomm_vec: phase_5a_decomm_vec_includes_i,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<(Phase5Com1, Phase5ADecom1, HomoELGamalProof<Secp256k1, Sha256>, DLogProof<Secp256k1, Sha256>)>> 
    {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round7 {
    party_num_int: u16,
    y_sum: Point<Secp256k1>,
    local_sig: LocalSignature, 
    message_bn: BigInt,
    phase5_com2: Phase5Com2,
    phase_5d_decom2: Phase5DDecom2,
    phase_5a_decomm_vec: Vec<Phase5ADecom1>,
}

impl Round7 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<(Phase5Com2, Phase5DDecom2)>,
        mut output: O,
    ) -> Result<Round8>
    where
        O: Push<Msg<Scalar<Secp256k1>>>,
    {
        let (commit5c_vec, decommit5d_vec): (Vec<Phase5Com2>, Vec<Phase5DDecom2>) = input
            .into_vec_including_me((self.phase5_com2, self.phase_5d_decom2))
            .into_iter()
            .unzip();
        
        let s_i = self.local_sig
            .phase5d(
                &decommit5d_vec,
                &commit5c_vec,
                &self.phase_5a_decomm_vec,
            )
            .expect("bad com 5d");

        output.push(Msg {
            sender: self.party_num_int,
            receiver: None,
            body: s_i.clone(),
        });
    
        Ok(Round8 {
            s_i,
            local_sig: self.local_sig, 
            y_sum: self.y_sum,
            message_bn: self.message_bn,
            party_num_int: self.party_num_int,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<(Phase5Com2, Phase5DDecom2)>> 
    {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round8 {
    s_i: Scalar<Secp256k1>,
    local_sig: LocalSignature, 
    y_sum: Point<Secp256k1>,
    message_bn: BigInt,
    party_num_int: u16,
}

impl Round8 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<Scalar<Secp256k1>>,
    ) -> Result<CompletedOfflineStage> {

        let s_i_vec: Vec<Scalar<Secp256k1>> = input.into_vec();

        let sig = self.local_sig
            .output_signature(&s_i_vec)
            .expect("verification failed");

        println!("party {:?} Output Signature: \n", self.party_num_int);
        println!("R: {:?}", sig.r);
        println!("s: {:?} \n", sig.s);
        println!("recid: {:?} \n", sig.recid.clone());

        // check sig against secp256k1
        //check_sig(&sig.r, &sig.s, &self.message_bn, &self.y_sum);

        Ok(CompletedOfflineStage{
            signature_rec_id: sig,
            y_sum_s: self.y_sum,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<Scalar<Secp256k1>>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct CompletedOfflineStage {
    pub signature_rec_id: SignatureRecid,
    pub y_sum_s: Point<Secp256k1>,
}

impl CompletedOfflineStage {
    pub fn public_key(&self) -> &Point<Secp256k1> {
        &self.y_sum_s
    }
}

/*
pub struct Round8 {
    local_signature: LocalSignature,
}

impl Round8 {
    pub fn new(
        message: &BigInt,
        completed_offline_stage: CompletedOfflineStagE,
    ) -> Result<(Self, PartialSignature)> {
        let local_signature = LocalSignature::phase7_local_sig(
            &completed_offline_stage.sign_keys.k_i,
            message,
            &completed_offline_stage.R,
            &completed_offline_stage.sigma_i,
            &completed_offline_stage.local_key.y_sum_s,
        );
        let partial = PartialSignature(local_signature.s_i.clone());
        Ok((Self { local_signature }, partial))
    }

    pub fn proceed_manual(self, sigs: &[PartialSignature]) -> Result<SignatureRecid> {
        let sigs = sigs.iter().map(|s_i| s_i.0.clone()).collect::<Vec<_>>();
        self.local_signature
            .output_signature(&sigs)
            .map_err(Error::Round7)
    }
}
*/
#[derive(Debug, Error)]
pub enum Error {
    #[error("round 1: {0:?}")]
    Round1(ErrorType),
    #[error("round 2 stage 3: {0:?}")]
    Round2Stage3(crate::common::Error),
    #[error("round 2 stage 4: {0:?}")]
    Round2Stage4(ErrorType),
    #[error("round 3: {0:?}")]
    Round3(ErrorType),
    #[error("round 5: {0:?}")]
    Round5(ErrorType),
    #[error("round 6: verify proof: {0:?}")]
    Round6VerifyProof(ErrorType),
    #[error("round 6: check sig: {0:?}")]
    Round6CheckSig(crate::common::Error),
    #[error("round 7: {0:?}")]
    Round7(crate::common::Error),
}

trait IteratorExt: Iterator {
    fn my_unzip<A>(self) -> Vec<A>
    where
        Self: Iterator<Item = A > + Sized,
    {
        let mut a = vec![];
        for a_i in self {
            a.push(a_i);
        }
        a
    }

    fn unzip4<A, B, C, D>(self) -> (Vec<A>, Vec<B>, Vec<C>, Vec<D>)
    where
        Self: Iterator<Item = (A, B, C, D)> + Sized,
    {
        let (mut a, mut b, mut c, mut d) = (vec![], vec![], vec![], vec![]);
        for (a_i, b_i, c_i, d_i) in self {
            a.push(a_i);
            b.push(b_i);
            c.push(c_i);
            d.push(d_i);
        }
        (a, b, c, d)
    }
}

impl<I> IteratorExt for I where I: Iterator {}
