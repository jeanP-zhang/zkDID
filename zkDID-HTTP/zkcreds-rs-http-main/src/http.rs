use crate::attrs::Attrs;
use crate::com_forest::gen_forest_memb_crs;
use crate::com_forest::ComForestRoots;
use crate::com_tree::*;
use crate::link::{
    link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs,
};
use crate::poseidon_utils::Bls12PoseidonCommitter;
use crate::poseidon_utils::Bls12PoseidonCrh;
use crate::pred::{gen_pred_crs, prove_pred};
use crate::proof_data_structures::{
    ForestProof, ForestProvingKey, ForestVerifyingKey, PredProof, PredProvingKey, PredVerifyingKey,
    TreeProof, TreeProvingKey, TreeVerifyingKey,
};
use crate::test_util::NameAndBirthYear;
use crate::test_util::{AgeChecker, Fr, NameAndBirthYearVar};
use actix_web::{get, http::header::ContentType, post, web, HttpResponse, Responder};
use ark_bls12_381::{Bls12_381 as E, Bls12_381, FrParameters, Parameters};
use ark_ec::bls12::Bls12;
use ark_ff::Fp256;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use base64::{decode, encode};
use lazy_static::lazy_static;
use linkg16::groth16;
use linkg16::groth16::{ProvingKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct Birth {
    name: String,
    date: u32,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct IssueResult {
    #[serde(rename = "personCom")]
    person_com: String,
    #[serde(rename = "authPath")]
    auth_path: String,
    #[serde(rename = "forestRoots")]
    forest_roots: String,
    #[serde(rename = "forestProof")]
    forest_proof: String,
    #[serde(rename = "treeProof")]
    tree_proof: String,
    #[serde(rename = "merkleRoot")]
    merkle_root: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PersonProofParas {
    birth: Birth,
    #[serde(rename = "authPath")]
    auth_path: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VerifyParas {
    vks: VKS,
    #[serde(rename = "personCom")]
    person_com: String,
    #[serde(rename = "forestRoots")]
    forest_roots: String,
    #[serde(rename = "forestProof")]
    forest_proof: String,
    #[serde(rename = "treeProof")]
    tree_proof: String,
    #[serde(rename = "personProof")]
    person_proof: String,
    #[serde(rename = "merkleRoot")]
    merkle_root: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PKS {
    #[serde(rename = "forestPk")]
    forest_pk: String,
    #[serde(rename = "treePk")]
    tree_pk: String,
    #[serde(rename = "agePk")]
    age_pk: String,
}

pub struct PksOrigin {
    forest_pk: ForestProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
    tree_pk: TreeProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
    age_pk: PredProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct VKS {
    #[serde(rename = "forestVk")]
    forest_vk: String,
    #[serde(rename = "treeVk")]
    tree_vk: String,
    #[serde(rename = "ageVk")]
    age_vk: String,
}

const EIGHTEEN_YEARS_AGO: u16 = 2004;
const TREE_HEIGHT: u32 = 3;
const NUM_TREES: usize = 2;

fn get_pks() -> PksOrigin {
    let mut rng = ark_std::test_rng();
    let forest_pk: ForestProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = gen_forest_memb_crs::<
        _,
        E,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >(&mut rng, NUM_TREES)
    .unwrap();

    let tree_pk: TreeProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = gen_tree_memb_crs::<
        _,
        E,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >(&mut rng, (), TREE_HEIGHT)
    .unwrap();

    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
    };
    let age_pk: PredProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = gen_pred_crs::<_, _, E, _, _, _, _, Bls12PoseidonCrh, Bls12PoseidonCrh>(
        &mut rng,
        age_checker.clone(),
    )
    .unwrap();

    PksOrigin {
        forest_pk: forest_pk,
        tree_pk: tree_pk,
        age_pk: age_pk,
    }
}

lazy_static! {
    static ref VKS_STATIC: VKS = {
        let pks: PksOrigin = get_pks();

        let tree_vk = pks.tree_pk.prepare_verifying_key();

        let forest_vk = pks.forest_pk.prepare_verifying_key();

        let age_vk = pks.age_pk.prepare_verifying_key();

        println!("VKS init");
        let vks = VKS {
            forest_vk: encode_forest_vk(forest_vk),
            tree_vk: encode_tree_vk(tree_vk),
            age_vk: encode_age_vk(age_vk),
        };
        return vks;
    };
}

#[get("/birth/vks")]
async fn get_vks() -> impl Responder {
    let vks: &VKS = &*VKS_STATIC;
    println!("vks:{:?}", vks);

    let result_serialized = serde_json::to_string(&vks).unwrap();
    HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(result_serialized)
}

#[get("/birth/ageChecker")]
async fn get_ageChecker() -> impl Responder {
    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
    };
    let mut buffer = Vec::new();
    let _ = age_checker.serialize(&mut buffer);
    let age_checker_serialized = serde_json::to_string(&buffer).unwrap();
    HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(encode(age_checker_serialized))
}

#[post("/birth/commit")]
async fn submit(birth: web::Json<Birth>) -> impl Responder {
    println!("new request from /birth/commit");
    println!("birth:{:?}", birth);
    let mut rng = ark_std::test_rng();

    let person = NameAndBirthYear::new(&mut rng, birth.name.as_bytes(), birth.date as u16);
    let person_com = Attrs::<_, Bls12PoseidonCommitter>::commit(&person.clone());
    println!("person:{:?}", person);
    println!("person_com:{:?}", person_com);
    let encoded = encode_fr(person_com);
    println!("encoded:{:?}", encoded);
    println!("====================");

    HttpResponse::Ok().body(encoded)
}

#[post("/birth/issue")]
async fn issue(person_com_encoded: String) -> impl Responder {
    println!("new request from /birth/issue");
    let mut rng = ark_std::test_rng();
    let pks: PksOrigin = get_pks();
    let person_com = decode_fr(person_com_encoded.clone());
    println!("person_com:{:?}", person_com);
    let forest_pk = pks.forest_pk;
    let tree_pk = pks.tree_pk;

    let leaf_idx = 2;
    let mut tree = ComTree::<_, Bls12PoseidonCrh, Bls12PoseidonCommitter>::empty((), TREE_HEIGHT);
    let auth_path: ComTreePath<_, Bls12PoseidonCrh, Bls12PoseidonCommitter> =
        tree.insert(leaf_idx, &person_com);

    let merkle_root = tree.root();
    let tree_proof = auth_path
        .prove_membership(&mut rng, &tree_pk, &(), person_com)
        .unwrap();
    let mut roots = ComForestRoots::new(NUM_TREES - 1);
    let root = tree.root();

    roots.roots.push(root);
    let forest_proof = roots
        .prove_membership(&mut rng, &forest_pk, merkle_root, person_com)
        .unwrap();

    let issue_result = IssueResult {
        person_com: person_com_encoded,
        auth_path: encode_auth_path(auth_path),
        forest_roots: encode_roots(roots),
        merkle_root: encode_fr(merkle_root.clone()),
        forest_proof: encode_forest_proof(forest_proof),
        tree_proof: encode_tree_proof(tree_proof),
    };
    let res = serde_json::to_string(&issue_result).unwrap();
    HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(res)
}

#[post("/birth/userProof")]
async fn user_proof(paras: web::Json<PersonProofParas>) -> impl Responder {
    println!("new request from /birth/userProof");
    let mut rng = ark_std::test_rng();
    let pks: PksOrigin = get_pks();

    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
    };

    let age_pk = pks.age_pk;

    let person = NameAndBirthYear::new(
        &mut rng,
        paras.birth.name.as_bytes(),
        paras.birth.date as u16,
    );

    let auth_path = decode_auth_path(paras.auth_path.clone());

    let user_proof_result = prove_pred(&mut rng, &age_pk, age_checker.clone(), person, &auth_path);
    let mut user_proof_string = String::new();
    match user_proof_result {
        Ok(user_proof) => {
            user_proof_string = encode_age_proof(user_proof);
        }
        Err(_) => user_proof_string = String::new(),
    }
    HttpResponse::Ok().body(user_proof_string)
}

#[post("/birth/verify")]
async fn verify(paras: web::Json<VerifyParas>) -> impl Responder {
    println!("new request from /birth/verify");
    let mut rng = ark_std::test_rng();
    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
    };
    let mut pred_inputs = PredPublicInputs::default();

    let age_vk = decode_age_vk(paras.vks.age_vk.clone());
    pred_inputs.prepare_pred_checker(&age_vk, &age_checker);

    let roots = decode_roots(paras.forest_roots.clone());

    let forest_vk = decode_forest_vk(paras.vks.forest_vk.clone());

    let tree_vk = decode_tree_vk(paras.vks.tree_vk.clone());

    // Now link everything together
    let link_vk = LinkVerifyingKey {
        pred_inputs: pred_inputs.clone(),
        prepared_roots: roots.prepare(&forest_vk).unwrap(),
        forest_verif_key: forest_vk.clone(),
        tree_verif_key: tree_vk.clone(),
        pred_verif_keys: vec![age_vk.clone(); 1],
    };

    let person_com = decode_fr(paras.person_com.clone());

    let forest_proof = decode_forest_proof(paras.forest_proof.clone());

    let tree_proof = decode_tree_proof(paras.tree_proof.clone());

    let age_proof = decode_age_proof(paras.person_proof.clone());

    let link_ctx = LinkProofCtx {
        attrs_com: person_com,
        merkle_root: decode_fr(paras.merkle_root.clone()),
        forest_proof: forest_proof.clone(),
        tree_proof: tree_proof.clone(),
        pred_proofs: vec![age_proof.clone(); 1],
        vk: link_vk.clone(),
    };
    let link_proof = link_proofs(&mut rng, &link_ctx);

    let proof_result = verif_link_proof(&link_proof, &link_vk).unwrap();

    #[derive(Deserialize, Serialize, Debug)]
    struct Result {
        result: bool,
    }
    let result = Result {
        result: proof_result,
    };
    let res = serde_json::to_string(&result).unwrap();
    HttpResponse::Ok()
        .content_type(ContentType::json())
        .body(res)
}

fn encode_forest_pk(
    forest_pk: ForestProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
) -> String {
    let mut buffer = Vec::new();
    let _ = forest_pk.serialize(&mut buffer);
    let forest_pk_serialized = serde_json::to_string(&buffer).unwrap();
    return encode(forest_pk_serialized);
}

fn decode_forest_pk(
    forest_pk_string: String,
) -> ForestProvingKey<
    Bls12<Parameters>,
    NameAndBirthYear,
    Bls12PoseidonCommitter,
    Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    Bls12PoseidonCrh,
> {
    let decoded = decode(&forest_pk_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let forest_pk: ForestProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = ForestProvingKey::deserialize(vec.as_slice()).unwrap();
    return forest_pk;
}

fn encode_forest_vk(
    forest_vk: ForestVerifyingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
) -> String {
    let mut buffer = Vec::new();
    let _ = forest_vk.serialize(&mut buffer);
    let forest_vk_serialized = serde_json::to_string(&buffer).unwrap();
    return encode(forest_vk_serialized);
}

fn decode_forest_vk(
    forest_vk_string: String,
) -> ForestVerifyingKey<
    Bls12<Parameters>,
    NameAndBirthYear,
    Bls12PoseidonCommitter,
    Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    Bls12PoseidonCrh,
> {
    let decoded = decode(&forest_vk_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let forest_vk: ForestVerifyingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = ForestVerifyingKey::deserialize(vec.as_slice()).unwrap();
    return forest_vk;
}

fn encode_tree_pk(
    tree_pk: TreeProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
) -> String {
    let mut buffer = Vec::new();
    let _ = tree_pk.serialize(&mut buffer);
    let tree_pk_serialized = serde_json::to_string(&buffer).unwrap();
    return encode(tree_pk_serialized);
}

fn decode_tree_pk(
    tree_pk_string: String,
) -> TreeProvingKey<
    Bls12<Parameters>,
    NameAndBirthYear,
    Bls12PoseidonCommitter,
    Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    Bls12PoseidonCrh,
> {
    let decoded = decode(&tree_pk_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let tree_pk: TreeProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = TreeProvingKey::deserialize(vec.as_slice()).unwrap();
    return tree_pk;
}

fn encode_tree_vk(
    tree_vk: TreeVerifyingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
) -> String {
    let mut buffer = Vec::new();
    let _ = tree_vk.serialize(&mut buffer);
    let forest_vk_serialized = serde_json::to_string(&buffer).unwrap();
    return encode(forest_vk_serialized);
}

fn decode_tree_vk(
    tree_vk_string: String,
) -> TreeVerifyingKey<
    Bls12<Parameters>,
    NameAndBirthYear,
    Bls12PoseidonCommitter,
    Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    Bls12PoseidonCrh,
> {
    let decoded = decode(&tree_vk_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let tree_vk: TreeVerifyingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = TreeVerifyingKey::deserialize(vec.as_slice()).unwrap();
    return tree_vk;
}

fn encode_age_pk(
    age_pk: PredProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
) -> String {
    let mut buffer = Vec::new();
    let _ = age_pk.serialize(&mut buffer);
    let age_pk_serialized = serde_json::to_string(&buffer).unwrap();
    return encode(age_pk_serialized);
}

fn decode_age_pk(
    age_pk_string: String,
) -> PredProvingKey<
    Bls12<Parameters>,
    NameAndBirthYear,
    NameAndBirthYearVar,
    Bls12PoseidonCommitter,
    Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    Bls12PoseidonCrh,
> {
    let decoded = decode(&age_pk_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let age_pk: PredProvingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = PredProvingKey::deserialize(vec.as_slice()).unwrap();
    return age_pk;
}

fn encode_age_vk(
    age_vk: PredVerifyingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
) -> String {
    let mut buffer = Vec::new();
    let _ = age_vk.serialize(&mut buffer);
    let age_vk_serialized = serde_json::to_string(&buffer).unwrap();
    return encode(age_vk_serialized);
}

fn decode_age_vk(
    age_vk_string: String,
) -> PredVerifyingKey<
    Bls12<Parameters>,
    NameAndBirthYear,
    NameAndBirthYearVar,
    Bls12PoseidonCommitter,
    Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    Bls12PoseidonCrh,
> {
    let decoded = decode(&age_vk_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let age_vk: PredVerifyingKey<
        Bls12<Parameters>,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = PredVerifyingKey::deserialize(vec.as_slice()).unwrap();
    return age_vk;
}

fn encode_vk(vk: VerifyingKey<E>) -> String {
    let mut buffer = Vec::new();
    let _ = vk.serialize(&mut buffer);
    let vk_serialized = serde_json::to_string(&buffer).unwrap();
    encode(vk_serialized)
}

fn decode_vk(vk_string: String) -> VerifyingKey<E> {
    let decoded = decode(&vk_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let vk: VerifyingKey<E> = VerifyingKey::deserialize(vec.as_slice()).unwrap();
    return vk;
}

fn decode_pk(pk: String) -> ProvingKey<E> {
    let decoded = decode(&pk).unwrap();
    // let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let groth16_pk: ProvingKey<Bls12_381> = ProvingKey::deserialize(decoded.as_slice()).unwrap();
    return groth16_pk;
}

fn encode_pk(pk: ProvingKey<E>) -> String {
    let mut buffer = Vec::new();
    let _ = pk.serialize(&mut buffer);
    // let pk_serialized = serde_json::to_string(&buffer).unwrap();
    encode(buffer)
}

fn encode_auth_path(
    com_tree_path: ComTreePath<Fr, Bls12PoseidonCrh, Bls12PoseidonCommitter>,
) -> String {
    let mut buffer = Vec::new();
    let _ = com_tree_path.serialize(&mut buffer);
    let auth_path_serialized = serde_json::to_string(&buffer).unwrap();
    encode(auth_path_serialized)
}

fn decode_auth_path(
    auth_path_string: String,
) -> ComTreePath<Fr, Bls12PoseidonCrh, Bls12PoseidonCommitter> {
    let decoded = decode(&auth_path_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let auth_path: ComTreePath<Fr, Bls12PoseidonCrh, Bls12PoseidonCommitter> =
        ComTreePath::deserialize(vec.as_slice()).unwrap();
    return auth_path;
}

fn encode_fr(fr: Fp256<FrParameters>) -> String {
    let mut buffer = Vec::new();
    let _ = fr.serialize(&mut buffer);
    let fr_serialized = serde_json::to_string(&buffer).unwrap();
    encode(fr_serialized)
}

fn decode_fr(fr_string: String) -> Fp256<FrParameters> {
    let decoded = decode(&fr_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let fr: Fp256<FrParameters> = Fp256::deserialize(vec.as_slice()).unwrap();
    return fr;
}

fn encode_proof(proof: groth16::Proof<Bls12_381>) -> String {
    let mut buffer = Vec::new();
    let _ = proof.serialize(&mut buffer);
    let proof_serialized = serde_json::to_string(&buffer).unwrap();
    encode(proof_serialized)
}

fn decode_proof(proof_string: String) -> groth16::Proof<Bls12_381> {
    let decoded = decode(&proof_string).unwrap();
    let proof: groth16::Proof<Bls12_381> = groth16::Proof::deserialize(decoded.as_slice()).unwrap();
    return proof;
}

fn encode_forest_proof(
    forest_proof: ForestProof<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
) -> String {
    let mut buffer = Vec::new();
    let _ = forest_proof.serialize(&mut buffer);
    let forest_proof_serialized = serde_json::to_string(&buffer).unwrap();
    encode(forest_proof_serialized)
}

fn decode_forest_proof(
    forest_proof_string: String,
) -> ForestProof<
    Bls12<Parameters>,
    NameAndBirthYear,
    Bls12PoseidonCommitter,
    Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    Bls12PoseidonCrh,
> {
    let decoded = decode(&forest_proof_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let forest_proof: ForestProof<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = ForestProof::deserialize(vec.as_slice()).unwrap();
    return forest_proof;
}

fn encode_tree_proof(
    tree_proof: TreeProof<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
) -> String {
    let mut buffer = Vec::new();
    let _ = tree_proof.serialize(&mut buffer);
    let tree_proof_serialized = serde_json::to_string(&buffer).unwrap();
    encode(tree_proof_serialized)
}

fn decode_tree_proof(
    tree_proof_string: String,
) -> TreeProof<
    Bls12<Parameters>,
    NameAndBirthYear,
    Bls12PoseidonCommitter,
    Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    Bls12PoseidonCrh,
> {
    let decoded = decode(&tree_proof_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let tree_proof: TreeProof<
        Bls12<Parameters>,
        NameAndBirthYear,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = TreeProof::deserialize(vec.as_slice()).unwrap();
    return tree_proof;
}

fn encode_age_proof(
    age_proof: PredProof<
        Bls12<Parameters>,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    >,
) -> String {
    let mut buffer = Vec::new();
    let _ = age_proof.serialize(&mut buffer);
    let age_proof_serialized = serde_json::to_string(&buffer).unwrap();
    encode(age_proof_serialized)
}

fn decode_age_proof(
    age_proof_string: String,
) -> PredProof<
    Bls12<Parameters>,
    NameAndBirthYear,
    NameAndBirthYearVar,
    Bls12PoseidonCommitter,
    Bls12PoseidonCommitter,
    Bls12PoseidonCrh,
    Bls12PoseidonCrh,
> {
    let decoded = decode(&age_proof_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let age_proof: PredProof<
        Bls12<Parameters>,
        NameAndBirthYear,
        NameAndBirthYearVar,
        Bls12PoseidonCommitter,
        Bls12PoseidonCommitter,
        Bls12PoseidonCrh,
        Bls12PoseidonCrh,
    > = PredProof::deserialize(vec.as_slice()).unwrap();
    return age_proof;
}

fn encode_roots(roots: ComForestRoots<Fp256<FrParameters>, Bls12PoseidonCrh>) -> String {
    let mut buffer = Vec::new();
    let _ = roots.serialize(&mut buffer);
    let roots_serialized = serde_json::to_string(&buffer).unwrap();
    encode(roots_serialized)
}

fn decode_roots(roots_string: String) -> ComForestRoots<Fp256<FrParameters>, Bls12PoseidonCrh> {
    let decoded = decode(&roots_string).unwrap();
    let vec: Vec<u8> = serde_json::from_slice(decoded.as_slice()).unwrap();
    let roots: ComForestRoots<Fp256<FrParameters>, Bls12PoseidonCrh> =
        ComForestRoots::deserialize(vec.as_slice()).unwrap();
    return roots;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_util::NameAndBirthYear;

    use ark_bls12_381::Bls12_381 as E;

    #[test]
    fn test_forest_pk() {
        let mut rng = ark_std::test_rng();
        let forest_pk = gen_forest_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            Bls12PoseidonCommitter,
            Bls12PoseidonCommitter,
            Bls12PoseidonCrh,
            Bls12PoseidonCrh,
        >(&mut rng, NUM_TREES)
        .unwrap();

        let forest_pk_encode = encode_forest_pk(forest_pk);
        println!("forest_pk_encode:{:?}", forest_pk_encode);
    }

    #[test]
    fn test_tree_pk() {
        let mut rng = ark_std::test_rng();
        let tree_pk = gen_tree_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            Bls12PoseidonCommitter,
            Bls12PoseidonCommitter,
            Bls12PoseidonCrh,
            Bls12PoseidonCrh,
        >(&mut rng, (), 2)
        .unwrap();
        let tree_pk_encode = encode_tree_pk(tree_pk);
        println!("tree_pk_encode:{:?}", tree_pk_encode);
    }

    #[test]
    fn test_age_pk() {
        let mut rng = ark_std::test_rng();
        let age_checker = AgeChecker {
            threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
        };
        let age_pk: PredProvingKey<
            Bls12<Parameters>,
            NameAndBirthYear,
            NameAndBirthYearVar,
            Bls12PoseidonCommitter,
            Bls12PoseidonCommitter,
            Bls12PoseidonCrh,
            Bls12PoseidonCrh,
        > = gen_pred_crs::<
            _,
            _,
            Bls12_381,
            _,
            _,
            Bls12PoseidonCommitter,
            Bls12PoseidonCommitter,
            Bls12PoseidonCrh,
            Bls12PoseidonCrh,
        >(&mut rng, age_checker.clone())
        .unwrap();

        let age_pk_encode = encode_age_pk(age_pk);
        println!("age_pk_encode:{:?}", age_pk_encode);
    }

    #[test]
    fn test_person_com() {
        let birth: Birth = Birth {
            name: "shangsan".to_string(),
            date: 1992,
        };
        let mut rng = ark_std::test_rng();

        let person = NameAndBirthYear::new(&mut rng, birth.name.as_bytes(), birth.date as u16);
        let person_com = Attrs::<_, Bls12PoseidonCommitter>::commit(&person);
        println!("person_com:{:?}\n", encode_fr(person_com.clone()));
    }

    #[test]
    fn test_verify_origin() {
        let mut rng = ark_std::test_rng();
        let age_checker = AgeChecker {
            threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
        };

        // Forest predicate
        let forest_pk = gen_forest_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            Bls12PoseidonCommitter,
            Bls12PoseidonCommitter,
            Bls12PoseidonCrh,
            Bls12PoseidonCrh,
        >(&mut rng, NUM_TREES)
        .unwrap();
        let forest_vk = forest_pk.prepare_verifying_key();
        // Tree predicate
        let tree_pk = gen_tree_memb_crs::<
            _,
            E,
            NameAndBirthYear,
            Bls12PoseidonCommitter,
            Bls12PoseidonCommitter,
            Bls12PoseidonCrh,
            Bls12PoseidonCrh,
        >(&mut rng, (), TREE_HEIGHT)
        .unwrap();
        let tree_vk = tree_pk.prepare_verifying_key();

        // Age predicate
        // We choose that anyone born in 2004 or earlier satisfies our predicate

        let age_pk = gen_pred_crs::<_, _, E, _, _, _, _, Bls12PoseidonCrh, Bls12PoseidonCrh>(
            &mut rng,
            age_checker.clone(),
        )
        .unwrap();
        let age_vk = age_pk.prepare_verifying_key();

        // let pks: &PKS = &*PKS_STATIC;
        // let vks: &VKS = &*VKS_STATIC;

        // let forest_pk = decode_forest_pk(pks.forest_pk.clone());

        // let tree_pk = decode_tree_pk(pks.tree_pk.clone());

        // let age_pk = decode_age_pk(pks.age_pk.clone());

        // let forest_vk = decode_forest_vk(vks.forest_vk.clone());

        // let tree_vk = decode_tree_vk(vks.tree_vk.clone());

        // let age_vk = decode_age_vk(vks.age_vk.clone());

        println!("forest_vk:{:?}\n", encode_forest_vk(forest_vk.clone()));
        println!("tree_vk:{:?}\n", encode_tree_vk(tree_vk.clone()));
        println!("age_vk:{:?}\n", encode_age_vk(age_vk.clone()));
        println!("rng:{:?}\n", rng);
        //
        // Start proving things
        //

        // let mut rng = ark_std::test_rng();
        // Make a attribute to put in the tree
        // let person = NameAndBirthYear::new(&mut rng, birth.name.as_bytes(), birth.date as u16);
        // let person_com = Attrs::<_, Bls12PoseidonCommitter>::commit(&person);
        // println!("person_com:{:?}\n", encode_fr(person_com.clone()));
        let birth: Birth = Birth {
            name: "zhangsan".to_string(),
            date: 1992,
        };
        let person = NameAndBirthYear::new(&mut rng, birth.name.as_bytes(), birth.date as u16);
        let person_com = Attrs::<_, Bls12PoseidonCommitter>::commit(&person.clone());
        // let person_com = decode_fr(encode_fr(person_com));

        // Make a tree and "issue", i.e., put the person commitment in the tree at index 17
        let leaf_idx = 2;
        let mut tree =
            ComTree::<_, Bls12PoseidonCrh, Bls12PoseidonCommitter>::empty((), TREE_HEIGHT);
        let auth_path: ComTreePath<_, Bls12PoseidonCrh, Bls12PoseidonCommitter> =
            tree.insert(leaf_idx, &person_com);

        println!("auth_path:{:?}\n", encode_auth_path(auth_path.clone()));

        // let auth_path = decode_auth_path(encode_auth_path(auth_path));

        // The person can now prove membership in the tree. Calculate the root and prove wrt that
        // root.
        let merkle_root = tree.root();
        let tree_proof = auth_path
            .prove_membership(&mut rng, &tree_pk, &(), person_com)
            .unwrap();

        // let tree_proof = decode_tree_proof(encode_tree_proof(tree_proof));

        // Prove that the tree is in the forest
        // Make a forest of 10 trees, with our tree occursing at a random index in the forest
        let mut roots = ComForestRoots::new(NUM_TREES - 1);
        let root = tree.root();

        roots.roots.push(root);
        let forest_proof = roots
            .prove_membership(&mut rng, &forest_pk, merkle_root, person_com)
            .unwrap();

        // Prove the predicate
        let age_proof =
            prove_pred(&mut rng, &age_pk, age_checker.clone(), person, &auth_path).unwrap();

        let age_proof = decode_age_proof(encode_age_proof(age_proof));

        // Collect the predicate public inputs
        let mut pred_inputs = PredPublicInputs::default();
        pred_inputs.prepare_pred_checker(&age_vk, &age_checker);

        // Now link everything together
        let link_vk = LinkVerifyingKey {
            pred_inputs: pred_inputs.clone(),
            prepared_roots: roots.prepare(&forest_vk).unwrap(),
            forest_verif_key: forest_vk.clone(),
            tree_verif_key: tree_vk.clone(),
            pred_verif_keys: vec![age_vk.clone(); 1],
        };
        let link_ctx = LinkProofCtx {
            attrs_com: person_com,
            merkle_root: root,
            forest_proof: forest_proof.clone(),
            tree_proof: tree_proof.clone(),
            pred_proofs: vec![age_proof.clone(); 1],
            vk: link_vk.clone(),
        };
        let link_proof = link_proofs(&mut rng, &link_ctx);

        // Verify the link proof
        let result = verif_link_proof(&link_proof, &link_vk).unwrap();
        println!("result:{}", result.to_string());
        assert!(result)
    }

    #[test]
    fn test_verify() {
        let mut rng = ark_std::test_rng();
        let birth: Birth = Birth {
            name: "zhangsan".to_string(),
            date: 2020,
        };
        let pks: PksOrigin = get_pks();
        let vks: &VKS = &*VKS_STATIC;
        println!("vks:{:?}", vks);
        let forest_pk = pks.forest_pk;
        let tree_pk = pks.tree_pk;
        let age_pk = pks.age_pk;
        let forest_vk = decode_forest_vk(vks.forest_vk.clone());
        let tree_vk = decode_tree_vk(vks.tree_vk.clone());
        let age_vk = decode_age_vk(vks.age_vk.clone());

        let age_checker = AgeChecker {
            threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
        };

        let mut pred_inputs = PredPublicInputs::default();

        let person = NameAndBirthYear::new(&mut rng, birth.name.as_bytes(), birth.date as u16);
        let person_com = Attrs::<_, Bls12PoseidonCommitter>::commit(&person.clone());

        println!("person_com:{:?}", encode_fr(person_com.clone()));

        pred_inputs.prepare_pred_checker(&age_vk, &age_checker);

        let leaf_idx = 2;
        let mut tree =
            ComTree::<_, Bls12PoseidonCrh, Bls12PoseidonCommitter>::empty((), TREE_HEIGHT);
        let auth_path: ComTreePath<_, Bls12PoseidonCrh, Bls12PoseidonCommitter> =
            tree.insert(leaf_idx, &person_com);
        println!("auth_path:{:?}\n", encode_auth_path(auth_path.clone()));

        let merkle_root = tree.root();
        let tree_proof = auth_path
            .prove_membership(&mut rng, &tree_pk, &(), person_com)
            .unwrap();
        let mut roots = ComForestRoots::new(NUM_TREES - 1);
        let root = tree.root();

        roots.roots.push(root);
        let forest_proof = roots
            .prove_membership(&mut rng, &forest_pk, merkle_root, person_com)
            .unwrap();

        println!("roots:{:?}", encode_roots(roots.clone()));
        println!("merkle_root:{:?}", encode_fr(root.clone()));
        println!(
            "forest_proof:{:?}",
            encode_forest_proof(forest_proof.clone())
        );
        println!("tree_proof:{:?}", encode_tree_proof(tree_proof.clone()));

        let age_proof =
            prove_pred(&mut rng, &age_pk, age_checker.clone(), person, &auth_path).unwrap();
        println!("age_proof:{:?}", encode_age_proof(age_proof.clone()));

        // Now link everything together
        let link_vk = LinkVerifyingKey {
            pred_inputs: pred_inputs.clone(),
            prepared_roots: roots.prepare(&forest_vk).unwrap(),
            forest_verif_key: forest_vk.clone(),
            tree_verif_key: tree_vk.clone(),
            pred_verif_keys: vec![age_vk.clone(); 1],
        };
        let link_ctx = LinkProofCtx {
            attrs_com: person_com,
            merkle_root: root,
            forest_proof: forest_proof.clone(),
            tree_proof: tree_proof.clone(),
            pred_proofs: vec![age_proof.clone(); 1],
            vk: link_vk.clone(),
        };
        let link_proof = link_proofs(&mut rng, &link_ctx);
        let result = verif_link_proof(&link_proof, &link_vk).unwrap();
        println!("result:{}", result.to_string());
        assert!(result)
    }

    #[test]
    fn test_auth_path() {
        let person_com_encoded = "WzQ5LDEyMCwyMDIsOTYsMzksMTk4LDUxLDE4LDQxLDExOSwxNTMsMjM4LDE3Niw2Myw3LDE1NiwyMDUsMTE0LDEwMSw2LDE3NiwxMzMsOSwwLDI0LDUwLDYyLDI0MiwxMDQsMTY2LDE3OSwyOV0=".to_string();
        let pks: PksOrigin = get_pks();
        let person_com = decode_fr(person_com_encoded.clone());

        let leaf_idx = 2;
        let mut tree =
            ComTree::<_, Bls12PoseidonCrh, Bls12PoseidonCommitter>::empty((), TREE_HEIGHT);
        let auth_path: ComTreePath<_, Bls12PoseidonCrh, Bls12PoseidonCommitter> =
            tree.insert(leaf_idx, &person_com);

        println!("auth_path:{:?}\n", encode_auth_path(auth_path));
    }

    #[test]
    fn test_forest_proof() {
        let person_com_encoded = "WzQ5LDEyMCwyMDIsOTYsMzksMTk4LDUxLDE4LDQxLDExOSwxNTMsMjM4LDE3Niw2Myw3LDE1NiwyMDUsMTE0LDEwMSw2LDE3NiwxMzMsOSwwLDI0LDUwLDYyLDI0MiwxMDQsMTY2LDE3OSwyOV0=".to_string();
        let mut rng = ark_std::test_rng();
        let pks: PksOrigin = get_pks();
        let person_com = decode_fr(person_com_encoded.clone());
        let forest_pk = pks.forest_pk;

        let leaf_idx = 2;
        let mut tree =
            ComTree::<_, Bls12PoseidonCrh, Bls12PoseidonCommitter>::empty((), TREE_HEIGHT);
        let merkle_root = tree.root();
        let mut roots = ComForestRoots::new(NUM_TREES - 1);
        let root = tree.root();

        roots.roots.push(root);
        let forest_proof = roots
            .prove_membership(&mut rng, &forest_pk, merkle_root, person_com)
            .unwrap();
        println!(
            "forest_proof:{:?}",
            encode_forest_proof(forest_proof.clone())
        );
    }

    #[test]
    fn test_tree_proof() {
        let person_com_encoded = "WzQ5LDEyMCwyMDIsOTYsMzksMTk4LDUxLDE4LDQxLDExOSwxNTMsMjM4LDE3Niw2Myw3LDE1NiwyMDUsMTE0LDEwMSw2LDE3NiwxMzMsOSwwLDI0LDUwLDYyLDI0MiwxMDQsMTY2LDE3OSwyOV0=".to_string();
        let mut rng = ark_std::test_rng();
        let pks: PksOrigin = get_pks();
        let person_com = decode_fr(person_com_encoded.clone());
        let tree_pk = pks.tree_pk;

        let leaf_idx = 2;
        let mut tree =
            ComTree::<_, Bls12PoseidonCrh, Bls12PoseidonCommitter>::empty((), TREE_HEIGHT);
        let auth_path: ComTreePath<_, Bls12PoseidonCrh, Bls12PoseidonCommitter> =
            tree.insert(leaf_idx, &person_com);
        let tree_proof = auth_path
            .prove_membership(&mut rng, &tree_pk, &(), person_com)
            .unwrap();
        println!("tree_proof:{:?}", encode_tree_proof(tree_proof.clone()));
    }

    #[test]
    fn test_age_proof() {
        let auth_path = "WzMyLDAsMCwwLDAsMCwwLDAsNDksMTIwLDIwMiw5NiwzOSwxOTgsNTEsMTgsNDEsMTE5LDE1MywyMzgsMTc2LDYzLDcsMTU2LDIwNSwxMTQsMTAxLDYsMTc2LDEzMyw5LDAsMjQsNTAsNjIsMjQyLDEwNCwxNjYsMTc5LDI5LDMyLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDAsMCwwLDEsMCwwLDAsMCwwLDAsMCwxMjcsMjI1LDM1LDk1LDgxLDIwMyw4NSwxMjAsMjE2LDIzNSwxMDMsMjIyLDE3NywxMDAsODgsMTA0LDI1NSwxNjEsMjM3LDIyLDE3OCwxNzUsOTEsOTgsMjYsMjUzLDc3LDExMiwxNSwxMTgsMTkzLDIsOSwxODQsNjMsODksMTMzLDY0LDE0MCwxMjAsMjMwLDI0LDE4NywyMzMsMTU3LDE4MCw2MiwzNiw5NCwxNTEsMjA0LDE3OSwyNDUsMTcyLDIxNSwxMDgsMTc2LDE5OCwyNDgsMjksNywxNSwyMzMsNTYsMjI1LDEzMywzLDIwMiw5OCw5Miw4MywyMjIsMTM3LDI0MSwyMzMsNDUsMTUzLDI0MCwxOTgsMTQxLDI1MSwyMjQsNDAsMjA4LDEzLDE2OCwxMDIsMTcwLDE2MSwyNDAsMTk5LDIyMywyNTIsMTk4LDIzNywzM10=".to_string();
        let mut rng = ark_std::test_rng();
        let pks: PksOrigin = get_pks();
        let age_pk = pks.age_pk;
        let age_checker = AgeChecker {
            threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
        };
        let auth_path = decode_auth_path(auth_path);

        let birth: Birth = Birth {
            name: "zhangsan".to_string(),
            date: 1992,
        };
        let person = NameAndBirthYear::new(&mut rng, birth.name.as_bytes(), birth.date as u16);
        let age_proof =
            prove_pred(&mut rng, &age_pk, age_checker.clone(), person, &auth_path).unwrap();

        println!("用户证明:{:?}", encode_age_proof(age_proof.clone()));
    }

    #[test]
    fn test_checker() {
        let age_checker = AgeChecker {
            threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
        };
        let mut buffer = Vec::new();
        let _ = age_checker.serialize(&mut buffer);
        let age_checker_serialized = serde_json::to_string(&buffer).unwrap();
        println!("checker:{:?}", encode(age_checker_serialized));
    }
}
