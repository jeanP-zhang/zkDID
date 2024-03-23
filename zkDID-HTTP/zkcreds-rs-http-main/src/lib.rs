pub mod attrs;
pub mod birth;
pub mod com_forest;
pub mod com_tree;
pub mod compressed_pedersen;
pub mod link;
pub mod multishow;
pub mod poseidon_utils;
pub mod pred;
pub mod proof_data_structures;
pub mod pseudonymous_show;
pub mod revealing_multishow;
pub mod sparse_merkle;
pub mod test_util;
pub mod zk_utils;

pub mod http;
#[cfg(feature = "python")]
pub mod python_exports;

pub type Error = Box<dyn ark_std::error::Error>;

use actix_web::{App, HttpServer};
pub use zk_utils::Bytestring;

use crate::http::{get_ageChecker, get_vks, issue, submit, user_proof, verify};
use ark_crypto_primitives::commitment::{constraints::CommitmentGadget, CommitmentScheme};

pub type Com<C> = <C as CommitmentScheme>::Output;
pub type ComVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::OutputVar;
pub type ComNonce<C> = <C as CommitmentScheme>::Randomness;
pub type ComNonceVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::RandomnessVar;
pub type ComParam<C> = <C as CommitmentScheme>::Parameters;
pub type ComParamVar<C, CG, F> = <CG as CommitmentGadget<C, F>>::ParametersVar;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(submit)
            .service(issue)
            .service(verify)
            .service(get_vks)
            .service(user_proof)
            .service(get_ageChecker)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
