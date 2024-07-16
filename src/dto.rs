use serde::{Deserialize, Serialize};
use crate::proof::RapidSnarkProof;

#[derive(Serialize, Deserialize)]
pub(crate) struct ProvingOutput {
    pub public_inputs: Vec<String>,
    pub proof: RapidSnarkProof,
}
