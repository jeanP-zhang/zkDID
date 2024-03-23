use zkcreds::{
    attrs::Attrs,
    com_forest::{gen_forest_memb_crs, ComForestRoots},
    com_tree::{gen_tree_memb_crs, ComTree, ComTreePath},
    link::{link_proofs, verif_link_proof, LinkProofCtx, LinkVerifyingKey, PredPublicInputs},
    poseidon_utils::{Bls12PoseidonCommitter, Bls12PoseidonCrh},
    pred::{gen_pred_crs, prove_pred},
    test_util::{AgeChecker, NameAndBirthYear},
};

use ark_bls12_381::{Bls12_381 as E, Fr};
use criterion::Criterion;

const EIGHTEEN_YEARS_AGO: u16 = 2004;
const LOG2_NUM_LEAVES: u32 = 31;
const LOG2_NUM_TREES: u32 = 8;
const TREE_HEIGHT: u32 = LOG2_NUM_LEAVES + 1 - LOG2_NUM_TREES;
const NUM_TREES: usize = 2usize.pow(LOG2_NUM_TREES);

// This benchmarks the linkage functions as the number of predicates increases
pub fn bench_linkage(c: &mut Criterion) {
    let mut rng = ark_std::test_rng();

    //
    // Generate CRSs
    //

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
    let age_checker = AgeChecker {
        threshold_birth_year: Fr::from(EIGHTEEN_YEARS_AGO),
    };
    let age_pk = gen_pred_crs::<_, _, E, _, _, _, _, Bls12PoseidonCrh, Bls12PoseidonCrh>(
        &mut rng,
        age_checker.clone(),
    )
    .unwrap();
    let age_vk = age_pk.prepare_verifying_key();

    //
    // Start proving things
    //

    // Make a attribute to put in the tree
    let person = NameAndBirthYear::new(&mut rng, b"Andrew", 1992);
    let person_com = Attrs::<_, Bls12PoseidonCommitter>::commit(&person);

    // Make a tree and "issue", i.e., put the person commitment in the tree at index 17
    let leaf_idx = 17;
    let mut tree = ComTree::<_, Bls12PoseidonCrh, Bls12PoseidonCommitter>::empty((), TREE_HEIGHT);
    let auth_path: ComTreePath<_, Bls12PoseidonCrh, Bls12PoseidonCommitter> =
        tree.insert(leaf_idx, &person_com);

    // The person can now prove membership in the tree. Calculate the root and prove wrt that
    // root.
    let merkle_root = tree.root();
    let tree_proof = auth_path
        .prove_membership(&mut rng, &tree_pk, &(), person_com)
        .unwrap();

    // Prove that the tree is in the forest
    // Make a forest of 10 trees, with our tree occursing at a random index in the forest
    let mut roots = ComForestRoots::new(NUM_TREES - 1);
    let root = tree.root();

    roots.roots.push(root);
    let forest_proof = roots
        .prove_membership(&mut rng, &forest_pk, merkle_root, person_com)
        .unwrap();

    // Prove the predicate
    let age_proof = prove_pred(&mut rng, &age_pk, age_checker.clone(), person, &auth_path).unwrap();

    for num_preds in (0..100).step_by(5) {
        // Collect the predicate public inputs
        let mut pred_inputs = PredPublicInputs::default();
        for _ in 0..num_preds {
            pred_inputs.prepare_pred_checker(&age_vk, &age_checker);
        }

        // Now link everything together
        let link_vk = LinkVerifyingKey {
            pred_inputs: pred_inputs.clone(),
            prepared_roots: roots.prepare(&forest_vk).unwrap(),
            forest_verif_key: forest_vk.clone(),
            tree_verif_key: tree_vk.clone(),
            pred_verif_keys: vec![age_vk.clone(); num_preds],
        };
        let link_ctx = LinkProofCtx {
            attrs_com: person_com,
            merkle_root: root,
            forest_proof: forest_proof.clone(),
            tree_proof: tree_proof.clone(),
            pred_proofs: vec![age_proof.clone(); num_preds],
            vk: link_vk.clone(),
        };
        c.bench_function(&format!("Proving linkage [np={}]", num_preds), |b| {
            b.iter(|| link_proofs(&mut rng, &link_ctx))
        });
        let link_proof = link_proofs(&mut rng, &link_ctx);
        crate::util::record_size(format!("Age [np={}]", num_preds), &link_proof);

        // Verify the link proof
        c.bench_function(&format!("Verifying linkage [np={}]", num_preds), |b| {
            b.iter(|| assert!(verif_link_proof(&link_proof, &link_vk).unwrap()))
        });
    }
}
