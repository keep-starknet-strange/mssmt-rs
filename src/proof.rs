//! Proofs are used to verify the consistency of a tree.
//!
//! A proof is a list of nodes that can be used to verify the consistency of a tree.
//!
//! A proof can be compressed into a bitvector.
//!
//! A compressed proof can be decompressed into a proof.
use std::sync::Arc;

use bitvec::order::Lsb0;
use bitvec::vec::BitVec;

use crate::{walk_up, Branch, ComputedNode, EmptyTree, Hasher, Leaf, Node, TreeError};

/// A merkle proof for a given key.
#[derive(Debug, Clone)]
pub struct Proof<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    nodes: Vec<Node<HASH_SIZE, H>>,
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> Proof<HASH_SIZE, H> {
    /// Creates a new proof from a list of nodes.
    pub fn new(nodes: Vec<Node<HASH_SIZE, H>>) -> Self {
        Self { nodes }
    }

    /// Returns the nodes in the proof.
    pub fn nodes(&self) -> &[Node<HASH_SIZE, H>] {
        &self.nodes
    }

    /// Verifies the proof against a leaf and a key.
    pub fn root<DbError: std::fmt::Debug>(
        &self,
        key: &[u8; HASH_SIZE],
        leaf: Leaf<HASH_SIZE, H>,
    ) -> Branch<HASH_SIZE, H> {
        // This can't fail
        walk_up::<HASH_SIZE, H, DbError>(
            key,
            leaf,
            &self
                .nodes
                .iter()
                .map(|node| Arc::new(node.clone()))
                .collect::<Vec<_>>(),
            |_, _, _, _| {},
        )
        .unwrap()
    }

    /// Compresses the proof into a compressed proof.
    pub fn compress(&self) -> CompressedProof<HASH_SIZE, H> {
        let empty_tree = EmptyTree::<HASH_SIZE, H>::empty_tree();
        let mut bits = BitVec::with_capacity(self.nodes.len());
        let mut nodes = Vec::new();
        for (i, node) in self.nodes.iter().enumerate() {
            if node.hash() == empty_tree[HASH_SIZE * 8 - i].hash() {
                bits.push(true);
            } else {
                bits.push(false);
                nodes.push(node.clone());
            }
        }
        CompressedProof::new(nodes, bits)
    }

    /// Verify a merkle proof for a given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key of the node to verify the proof for
    /// * `leaf` - The leaf node to verify the proof for
    /// * `proof` - The proof to verify
    /// * `root` - The expected root of the tree
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the proof is valid, otherwise returns an error.
    pub fn verify_merkle_proof<DbError>(
        &self,
        key: &[u8; HASH_SIZE],
        leaf: Leaf<HASH_SIZE, H>,
        root_hash: [u8; HASH_SIZE],
    ) -> Result<(), TreeError<DbError>> {
        // Compute the root from the leaf and the proof
        let got_root = walk_up(
            key,
            leaf,
            &self
                .nodes
                .clone()
                .into_iter()
                .map(Arc::new)
                .collect::<Vec<_>>(),
            |_, _, _, _| {},
        )?;
        // Check if the computed root matches the expected root
        if got_root.hash() == root_hash {
            Ok(())
        } else {
            Err(TreeError::InvalidMerkleProof)
        }
    }
}

/// A compressed merkle proof for a given key.
/// We don't store all the nodes if they are empty.
pub struct CompressedProof<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> {
    nodes: Vec<Node<HASH_SIZE, H>>,
    bits: BitVec<u8, Lsb0>,
}

impl<const HASH_SIZE: usize, H: Hasher<HASH_SIZE> + Clone> CompressedProof<HASH_SIZE, H> {
    /// Creates a new compressed proof from a list of nodes and a bitvector.
    pub fn new(nodes: Vec<Node<HASH_SIZE, H>>, bits: BitVec<u8, Lsb0>) -> Self {
        Self { nodes, bits }
    }

    /// Decompresses the proof into a proof.
    pub fn decompress<DbError: std::fmt::Debug>(
        &self,
    ) -> Result<Proof<HASH_SIZE, H>, TreeError<DbError>> {
        let mut nodes = Vec::with_capacity(self.bits.len());
        let nb_expected_nodes = self.bits.count_zeros();
        if self.nodes.len() != nb_expected_nodes {
            return Err(TreeError::InvalidMerkleProof);
        }
        let empty_tree = EmptyTree::<HASH_SIZE, H>::empty_tree();
        let mut next_node = 0;
        for (i, bit) in self.bits.iter().enumerate() {
            if *bit {
                nodes.push(empty_tree[HASH_SIZE * 8 - i].clone());
            } else {
                nodes.push(self.nodes[next_node].clone());
                next_node += 1;
            }
        }
        Ok(Proof::new(nodes))
    }

    /// Encodes the proof into a byte vector.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(self.nodes.len() as u16).to_be_bytes());
        for node in self.nodes.iter() {
            encoded.extend_from_slice(&node.hash());
            encoded.extend_from_slice(&node.sum().to_be_bytes());
        }
        encoded.extend_from_slice(self.bits.as_raw_slice());
        encoded
    }

    /// Decodes a proof from a byte vector.
    pub fn decode(data: &[u8]) -> Self {
        let nb_nodes = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let mut nodes = Vec::new();
        let mut data_index = 2;
        for _ in 0..nb_nodes {
            let mut hash = [0u8; HASH_SIZE];
            hash.copy_from_slice(&data[data_index..data_index + HASH_SIZE]);
            data_index += HASH_SIZE;
            let sum = u64::from_be_bytes(data[data_index..data_index + 8].try_into().unwrap());
            data_index += 8;
            nodes.push(Node::Computed(ComputedNode::new(hash, sum)));
        }
        let bits = BitVec::<u8, Lsb0>::from_slice(&data[data_index..]);
        Self::new(nodes, bits)
    }
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;
    use crate::{CompactMSSMT, MemoryDb};
    use hex_literal::hex;

    #[test]
    fn test_mssmt_merkle_proof() {
        let db = Box::new(MemoryDb::<32, Sha256>::new());
        let mut mssmt = CompactMSSMT::<32, Sha256, ()>::new(db);
        mssmt.insert(&[1; 32], Leaf::new(vec![1], 1)).unwrap();
        let proof = mssmt.merkle_proof(&[0; 32]).unwrap();
        let compressed = proof.compress();
        assert_eq!(compressed.nodes.len(), 1);
        let decompressed = compressed.decompress::<()>().unwrap();
        proof
            .nodes
            .iter()
            .zip(decompressed.nodes.iter())
            .for_each(|(a, b)| {
                assert_eq!(a.hash(), b.hash());
            });
    }

    #[test]
    fn test_compressed_proof_encode_decode() {
        let db = Box::new(MemoryDb::<32, Sha256>::new());
        let mut mssmt = CompactMSSMT::<32, Sha256, ()>::new(db);
        mssmt.insert(&[1; 32], Leaf::new(vec![1], 1)).unwrap();
        let proof = mssmt.merkle_proof(&[0; 32]).unwrap();
        let compressed = proof.compress();
        let encoded = compressed.encode();
        let decoded = CompressedProof::<32, Sha256>::decode(&encoded);
        compressed
            .nodes
            .iter()
            .zip(decoded.nodes.iter())
            .for_each(|(a, b)| {
                assert_eq!(a.hash(), b.hash());
            });
        assert_eq!(compressed.bits, decoded.bits);
    }

    #[test]
    fn decode_proof() {
        let proof = "000d5e33603b6fc04e71c5bb9037922c3b82dbe97fee8bf7ad1141e63d9be1e37f070000000115ff8f1aa2fb6e0a9a429d7ad2943f8d6f5c5aac52a5ac97ba34b08467e064fc42270a9c000000001f94b81669aeea06116829ae6c1bb088352980bfe670e97d3e1881936eab07ebd444e264000000004b8d77876bfbdbb3df1d985bb274e56f5f24dc4f5a8c9cfdf66d42a167098169aeb645b70000000534ecae32445ab27a6948995c9bbb4c90ba726914712e3e5e617aa1b6155571b46eacad9900000006389b57888d1a6d1e0e49bd475c99e33d0d76e6c632da6ebb9b4cf69fafa10cd54e7444ed000000108dc8a6e26005098a57041edb8a8ab7efb312be0219e8c82222982a3ad8d1cfb99efedc210000002b03f9d45cebe1f6f2c431b8aa7ea4c3e00308f5b3e72d03ebee85dcf97f6072969e8b6e3a0000005674538dbbfa554ed4ab986d77966d9bde88df9f176cb1b50b18d333c0cdc37e97134619e60000009368c72d0e686b8b50812d592e3e7986fdeca248dc99860a13b1ee2b4b12539817323a17cf0000013f2625fb388690fd5fdde3653af7cfe50e4f7e4bad565cee682cfc42b7f28a00e5585247cd0000027b6f28ec879fd492ae93e3f9d558656b6523212974325b43555f39687f1603268aead6e549000004df05d54f97dc71216a7e5193f8ae3ee589b7f8941b91a5e6b617563e68a0835180dfff2224000009b96f048feeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0700";
        let compressed = CompressedProof::<32, Sha256>::decode(&hex::decode(proof).unwrap());
        let decompressed = compressed.decompress::<()>().unwrap();
        decompressed
            .nodes
            .iter()
            .zip(expected_nodes())
            .enumerate()
            .for_each(|(i, (node, hash))| {
                assert_eq!(node.hash(), hash, "failed for node {}", i + 1)
            });
    }

    fn expected_nodes() -> Vec<[u8; 32]> {
        vec![
            hex!("af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc"),
            hex!("5a61e238f07e3a8114e39670c1e5ff430913d5793028258cf8a49282efee4411"),
            hex!("a9ed7261d36f1df934db5cfc81e1ea6e7c7117203dc4b88ccf336e6385153ec1"),
            hex!("dd8023b710a813409dd35d7ffab8c71a7625eb15b5bdb981862a5d270b1622a3"),
            hex!("13fefdf542341f1f92be3d67058cc4e7eab1303c48ee7fb8873c9dd56c30eedc"),
            hex!("17a3d2b53dfb08a1ab386e6c6f846c78d1aee8c4521e558c01dafecfcda757f0"),
            hex!("8f945cfd43b0996b000314bc186816cae2e6698c11ca3749b2d7a00718fb8c3f"),
            hex!("b024dbaa5aa401f43071f273fdc98d13381628fe6b5cefd482ca8d64275cf29b"),
            hex!("38f542347e7b8ee5d194890efc220bdf3f49d967c8a3e69d7c113aa0a95d290d"),
            hex!("28c5d45761cf38ed4fb2d4820bc57b9e591a04e9623b1f46da49f3ffa9dbf506"),
            hex!("cb710c2bc64511ee93f9c6c09c530c9eead588ffe3a3bf81dfcaead04abb9627"),
            hex!("a7d596226ff12cc379a1c733f57f8adc54e6f58f572b1da849122381651b02fa"),
            hex!("42af08a53490158553d5138cfe380acfb49d6e1b4d3b223f1c9962bf9e076726"),
            hex!("8ead572e77bf1522e570e306096945faa70c27cf7fc92e4e412872865ebcd20d"),
            hex!("984935e54049d8e034222d45ca161aac3d6a2c8f555b596afe99c1f386fd3453"),
            hex!("77bb1e77db06fdade7f031b60c4135b77b73db113a7b1557fbdd5dc8812fa9e0"),
            hex!("f41887d1f352a2bc614c0db152932619fe892cb9c19eecf12c5195037a365042"),
            hex!("cecc8126135333b32a4fa1eb35c96370b95c55f216abe81bc1b742bbb0292a6c"),
            hex!("19ddf72883b507916d9e63f679dbd4b171058c992301a676165609744bb5206d"),
            hex!("c0db25d52879aef53e310593e346fc4f0ccd9e60847fdf55b995e955455b345f"),
            hex!("df532b345eccd565ccd6e7730422d7993a36ca9a3f7036378e96a57c38383d7a"),
            hex!("6db868361129285aeb542a3f8ed683895e75965dda29b2d0dcff2e7e63f3c9b1"),
            hex!("07780bc3ae3733959e06446eeaec1123de1b9ad71d5a14eddfc4652188e4eb11"),
            hex!("72d00b5cadb331bdd80e9d683891a6b272b4eb9e26b3e2502fa9576005f3080f"),
            hex!("b570fc8f3c92725895a743534485d1fb8771735631985f7464f014d2159848e9"),
            hex!("6fc0ab9322188733cf05fa7fbdf2e84697aac090695d94a38e4e91a334e6902e"),
            hex!("7c9ec4048ca793473058dbd8d2779b295b9be7842dc0afa839e60797f815d22f"),
            hex!("834563ff1274aa1dab643b8cf6743dd75d24e9405c658e28eaf6b4bf860c9c31"),
            hex!("7a659e4406a0198dbfae13a2b6475df88e617c34e31571defb6088e3aaf493cb"),
            hex!("3f60555aaaf52164e662c130fb4cba80c76f1dd6ae874c7ab042384affe5f168"),
            hex!("3904b025d0a4e3baa1e3d465e546d3522663e30b8771f1bfe6798a0c8993a3e9"),
            hex!("41cf4ae56ed981cd9bdc9683b9431e77c6158d4761d174e8a59b59063795b36b"),
            hex!("d604ca0d3eab232f4e2940163de8a251f0e18c8be906f93a3bc2fd1aba7b7b53"),
            hex!("c1d8a912dc87d709492ebc43cdb455a2d8a97946c8621c634008d102e734d32a"),
            hex!("fe4202d6777191febf25953a1ea8c1f320dc7e504ab47a4bb294d6f0ed7db31a"),
            hex!("f0bcb7d86dc0d48fc48fcd0d11da647ecd1c3549d8cbde20e5bac5da18b91363"),
            hex!("b9c608c75bc18fc98f161622c877a422bffeebcef04ed9905767977cd1c7f2cc"),
            hex!("41136d8d973fa17734e1ccd8c40d77b08ffa57b1dc712aabe44e09ea285a0ef5"),
            hex!("14cee4320445fad2fac70edb932715b846a6a325a9942839542444009a5c3132"),
            hex!("67dc49976891cfcbff3ca95753be46666d52c5079b1eb968f5ac27e1d0852d07"),
            hex!("66a0328c81e9d9aaee4a0f1c30cc2e29a384250aae31a23f25da007d815acd05"),
            hex!("f70017eef9ae9e05a15574b7ad6ea7f8b31a566505794f224f433adf06a68397"),
            hex!("f4b51e27de77186c31918b2781ea450c6156cf60f1f1e637a7f87f558c62f26c"),
            hex!("59eb8d883449b591a51a811b5604dffa179aa47d65f6fd17d743cf84a609d50c"),
            hex!("754a6abe5d90e5afdaeeb01ccee0f27d0f700bcb919611343e37826ba6725ddf"),
            hex!("7abb93a7d81af26dd267e86dc7f8a318539e33a03cf10082713d0dcb7f36265d"),
            hex!("f753190660bdd2574231fa2051a2a78f3eec199b40be0ec019c1d299ef3605d7"),
            hex!("6fdad6ce632d70465803214f024b683cae8eaaecf33a544d748e8a269b651558"),
            hex!("bcb28ce7f4fb028ab06ee3ac2dc3d8c223fdb74daa078e27851785beaaed45ac"),
            hex!("d2cf3b3c2f01a7a303e65e6a337196d7028858ef668a794e825d8c12d4620664"),
            hex!("833497a764eeb2e73d994d780c45005be96d92fcd982a6c8e42f611e4e623d3c"),
            hex!("a68426049091bd22a748e7838ff8349bd75f117660083e443c4940b96f787056"),
            hex!("a8d4beaaff4176321b7e013fc346ade2a8b56b012ca10251a0a0b24655563404"),
            hex!("966ae608dbf2006bd3391cd0ebfb5399497aa5d66f65e0cbd271bdc54df2a0eb"),
            hex!("eac2ff48eb2eefac63b3747e8f899b7f4538fc3ad9e588b0c832ae85243e0cb5"),
            hex!("8dd5e5b4b5d8a0de9e13187327966b9804ca240addbd84534dcfe2305755d6d6"),
            hex!("ffc8e07bba38e0f37dfc30ebd5f271564541eb384dfe51e57a819e07e74b070c"),
            hex!("bfa84c5445a5fdd6a4c49847925e19c149374b793f8f7b51b09d899eedb346d2"),
            hex!("7889e9ecc31b56ec82452de12bafe84ef4a74d91b3598bd54230015582fb3107"),
            hex!("842f952d8dacf5a6a32977d356eb520efff0bf3cc3808ceeb9fac2b9790c33c5"),
            hex!("8e572ed7c0bbc06f1c79c5630ffaebf96b578c3ae711f3cc3d9a21056eefa221"),
            hex!("ff9f86b4aecd142809f322111759ed0ab40105f6b3ce6a46a5851eef9718cf5b"),
            hex!("4d4482f9ad98acad1de9845a667517d0ce406f262ef452bf544b0ea4174652ff"),
            hex!("7dae745740682775a48400d0b9588f0b00ed9f19d5d5e60453bba51b1e14f4ea"),
            hex!("0f96dae8381087eafad638190169621191231d3cb08bf1bf769a4106b9874746"),
            hex!("542d29516a86cc042fdb10cf2e7f659113820a3115351cf7ef8429667ebd9be5"),
            hex!("7e5196db96ce3ad71392020bc1b2fa104381f5ddd0379862156dd91bde4558cf"),
            hex!("9103711fac48e7787ccdee833d88c4fc7550f78e93e62ab619e02715a9c4d3f4"),
            hex!("160302c9f08b2f09fd640cb4ad87e1d97ad43678847076fbe7f09401c5e5ffaa"),
            hex!("e41db6a6d142b339f0366ba232f4c4380068c712e3aa98e9ff77390a55bed093"),
            hex!("9b3f53d9f2218d8c242fa8f53ec020bf7eb2951df4f388c10feb757514c16908"),
            hex!("5f87b386f1231159db52c4b2f0ca0acd8d55dd59a2dc738f87993f69378421ac"),
            hex!("3b7f51b2e98673a00d5dcc6345b4bf45f5aac73107f5b6cc8d5bd282f91d52b5"),
            hex!("c70404f43ad8bc288b7b1f91916e50f977516d09950fe15a6f8919dddff8986e"),
            hex!("2af0cd5d9853d611a65dd43c983e3b5545e95bd97c1bac645a21c44f7511e16b"),
            hex!("4e9bef2cc815bf0336845eb1ac2ef80858add4e06602319da2e9b1e182da410e"),
            hex!("1877f75e1f31934312cb0e223d8f0b2959d0e95404f878cc2a17bec856e13750"),
            hex!("46891b0545b164f18e3bc03c55ceb181bfc1457b4e654dc19ed0de98ac1b334a"),
            hex!("5be5dccc59e0efbd9dba622d18e411b0382ea6dd49db6cfcc446afbc01a78856"),
            hex!("b23c3617052698c38e08b10edd5c63b6875d57fd2dd0f4fbf840c908cb99cca4"),
            hex!("d41254423306dd354767076f911adf037963f2d3ac4118e8f4c05ca827ba486b"),
            hex!("4091414f0446039b4b4343264e12ad64b5de0a621cd5a3eb719a467ddcb38c69"),
            hex!("0a5521edd1f0daeea5b6db94e4d893617498c1a8a5e0bba61bef889360c15337"),
            hex!("0ee903ed970f70bb28b30795bdab30ad357663d823d86b70984a27dc5207f882"),
            hex!("06e92bc21329ae8a6c62642feac64d0ec823c7f0357ae192ededea53814e39bb"),
            hex!("6168f2e82b6e502fadc4ca3bd2450d3511e72dbbeb1fe068bac9a7bbdca42285"),
            hex!("2b0d5c073f18eaf6986db8fa51633130446a6c61a25a81539f1f478b371c7262"),
            hex!("7a4fb06fbc4c3331613a5e1a3261e5e677fbfe9dd6af6abd02f09e2b2552ad5b"),
            hex!("30863c863dc3f9fade27b49ec655b97f3f0b8fbb12ec22c895b89a17a992092b"),
            hex!("8a8353e486e5b7e0a9df049e4a8698ec9e00ac9be8334d06b9508db6cf9996df"),
            hex!("04ea8bb6b6c00faef11c804aa12fce3822bb7da8c4b2c7c45d7a786de95365d9"),
            hex!("640522708697998b74f12a79b4494f40bdd2ed485fa4d4e9ab7facb067dfc790"),
            hex!("069f795d3776f5efda0c183f5f8fff6b6318e4648775a564a8da5d38813d4e08"),
            hex!("c64b06a1e51b2d171e89b958052887039608f684c6dd944fddebc2a094df171d"),
            hex!("d835dc798f6f8d6e41f76243d1de9f278feec5f7d1f314c9b131a596372eb8cf"),
            hex!("ea6ac99aff4b4ac89b3d37eb85d2ae2001b912ab732e7aae6cc89c9dac171b4f"),
            hex!("b3e2527d86133cbb95881458ecf92feba792381344952f55af005d55f51705f5"),
            hex!("f76a5a266a79f17a13e7d8a3d7133579858d85a75299e7f629ba542ca5019651"),
            hex!("2c64e06d9f76b876b7ebb0a0f4f0ccc912fc84a397a3d6ded91ffaddee82c861"),
            hex!("c8bb0137d3b6f1146d2160bf756bc114883787d134e093edb0639d4aca26992d"),
            hex!("2e61715ba0d05ff7f68d596b124c7c877044d32c459d283ee4a922ec95feea13"),
            hex!("a8d62065d44bb4387dc4f901536c65be7475978b4d7d90f06c7530c43015aed4"),
            hex!("81e5b4f95f333dc03e4b54b78d2c5ff37ebede6b9ed2e8cdbe6d8a9a8433a696"),
            hex!("9894539a6511ca5356e84584c7bd894220c42d87a8593b2beddc64e16b96c03c"),
            hex!("ca45a9156be0fb3f4e5f8f52025fee1494986c6ebb2469e446b55f19daf16d1b"),
            hex!("22bfc35d37630538d3946c40eab8c140839d6e5f155e94bf71b5801389098d45"),
            hex!("f5b67dea1173b7bcf13b04fcfdaeb8b29cfdc1ac6ec49cc691c7ce1867952e27"),
            hex!("a29065cc93e1d98d65aad164a26d5d992c3521c4be6152d303714cb282481bc4"),
            hex!("a9255a6c00af337deefbb8ce94a5c98f315a817b2fe119a18896efda4bad8ee1"),
            hex!("e2b48549f5e2568a8f0a6d771dcdb3bd7ef8952a29d250750befc7c5b6ae5a07"),
            hex!("0c8f4ce8d7719607bb3cf60ea34f7d0fce9ece06cba6ec24100e92f546842eaf"),
            hex!("f029162746c555e57a164b72894bab28e974b88e064ffb6797c9323f6ee7bfbc"),
            hex!("b1d18d9d5ce49110ac5a3a37ac2a64a87518931408902a8c76abff0618389648"),
            hex!("5134851fe94e37caaf818cbbaab520ca98abc4c306b56a56dd7736482b1d8c5c"),
            hex!("46d435061683ec6d8983682aa492db54591a73e1f426a543b35c52d0a7a96bb8"),
            hex!("1fe2afb7422544bcdced59d29f70dcd24cc7a0718139ea91d3b49256795f26a9"),
            hex!("1efe412ccc21106986bd0b1fed6312ff96f32a3030241bc495c0a56a1864a00e"),
            hex!("195dcf087848fd07b59967bed6c1daead8dfa975c42e4717ba7a82af6f086aba"),
            hex!("265c4725fe9148fd3fa5c30ba9d7463a651ca95cc9e647d74a933e51b885dd2d"),
            hex!("fff586123c05b0fe1da74e69f9072f295dcbe076768120a9cf6c7ff77a6ad1dc"),
            hex!("7271132aa8bfe0e3646a8bede2a8e52c50d27e84488fd49f8f170e4fe053bae0"),
            hex!("9e3db6b22255e2e2f22c74c0821af9bebdedceb6d5022900adc93d0f49008b13"),
            hex!("1fdda341735ff99846c8768b4618cee76703af97bd2ae0281ed1e2a6e0756e4c"),
            hex!("1fb01fdd40a176533e19a5b858828563d228228858d11bf48bfb402e364b6322"),
            hex!("7c4de053b4dcf574c3ade7ebe2bf5d5d171149c42e62145657682511c58aed15"),
            hex!("6c4d4e7119a03ef8a7c06e0b0ea9e2895e990ace4c0dd369c64e70a94e8457b2"),
            hex!("214c6a75bfcae3f56a6f93121d2a7cf36d7c7c292a7f9be97346d26648c686f4"),
            hex!("dd9f6a56cd61c2a906ee04e6397bb72817672b871c70dc17ba7483ae5a687ac6"),
            hex!("b1608e367f212970f098c0a39dc9e641a03949deae3d4f5258d475c0413ec2cb"),
            hex!("e41f644456b1b25513d0cf121abc38ff655bcbf33b5153e656f05efbd5b106cf"),
            hex!("8e6b15fa79dc752f5543ee7d381f5d912fbaa1148697fbb11c2a1e401f6d9579"),
            hex!("9842683d5f93af51041b8141967a87253c31db6ee1ef0987e5e725698a83a9ed"),
            hex!("13afaf9e901f111e1696a5f192a518ff4ccfbbd0efc1178b3e05ea8ea56f74e5"),
            hex!("e21dbaf481f6ce7457314ebda93ba044bb7e74f3a3719ef0b16b0b15ac77258e"),
            hex!("9d4a9b7422038a567397ee3ee713969ed1d57bd52b2b7e7c25c5f82fc1243948"),
            hex!("ca977817d229f95b468a35e9ab9c8e396dc7b76eaf9f8bae380e1af9435a85d4"),
            hex!("217f24852933d72beb0c5eabc8759c6637c9995b753a6ad4e018513a93036bbe"),
            hex!("6e09bcee876a60fb359a3488585b230f8ab056df2c3b850b95f1602735f4c0f5"),
            hex!("738693f05051cf636f01e3e82c88979b72bac83fab4e874ec253a99cc96b740d"),
            hex!("c5a39aab7b18ced2f522af4d10c443fb2dd73a43db4408f679731fe9cc4dd72b"),
            hex!("3534bf3e5ea33b0eede684fd6a461511acfc1c017b0d1fa829f6835d4082e59a"),
            hex!("3b796839c1ac3b8f1e4c058af9dcda538e101428188346bd6224aee15d96ba60"),
            hex!("5924f813b3ed42adc7a8b42633db500e19877775ce8b4e099d0c49ee9fdf1fad"),
            hex!("5a08e6b0d00dce54d7a55399dcf5d50ddea3e1ff3ab3f016f3789ba3108a6666"),
            hex!("0a800b0d3539aacd06659ed91d78291d339a5183fc3262882073d55df542379f"),
            hex!("3dc7b1fededd60b516f9491ef2aefc527a978766641cdff50acb9eb8f8d9f6e3"),
            hex!("1796229f952526b0ae47e24815546abaec354a5d941b6452ef13c5f5b4ebba9f"),
            hex!("d6be99c7c32d3f4fb3337233f304953dc2726edba7284d9888194c24f58ad300"),
            hex!("c2bdc1f4daa23c0e9a89311917517340236b0eccd62536d49fed14145ee17624"),
            hex!("2c2922fe8373c8058e9cbdecff09fdcd6ddd0d8969ae6529f0d3c3e95a688cc1"),
            hex!("7c73beb202ad703eca38a2a49a83900a40e8fb02394a7a6e6cac154dc41ad405"),
            hex!("97bc36c342c7f3291a036f3cda6407dd2a917641aa9c68474615a4b9115e1035"),
            hex!("4c1989adbe3840b82bd01c0729206180e78fe1c57c6b083ddd100cee15d6507b"),
            hex!("45a8c7d46f1aff70174d3b3bb0ff9fe0dafa042906b42ef26dccd3d9ba5beb69"),
            hex!("109c4a273dca872b28eb314a3b7800488970a432417a1eb0b14c6ad6a31a8825"),
            hex!("472998072a85f873eb998722e11aa7248789f75f05745623db7c609c66defdf1"),
            hex!("05b0521648eea74bdc2aa7479ee0141c3bb050498ab38fc683d367774988244b"),
            hex!("da1b29e703753427f319381748129e7c5211a51568684e1c9b59666a08fc8b78"),
            hex!("2601be174bea1b1bf1c4e1f3705efba59f695c892e0288495f260991eae3b951"),
            hex!("509d61745d83c4f9a1a598be8625aac3c20ee4a44056edd2d78de22422cd3c12"),
            hex!("e1aeeccde9c78ff2f98c6f1475231865da17a35526fc664b02a932731768b92d"),
            hex!("010c7cc8b817f69b35a80c69a6680c6abfca28f2ee93c6f8c6f78db51ab24cf5"),
            hex!("b0ba3441b98780682df46d9576de635add4d11a8bd1fc7cc619aeb5ca1873763"),
            hex!("c6e0bbdd169985e81d819ee3c5a34a2b5895618ce378483ae630714ad57e88a6"),
            hex!("802e24936e9f30d6542e6d3ffe71d7cea5be09fad48f8568f63b43cd6f60fe63"),
            hex!("e0efad633867d94a3cf677fdbd55ad71e7b87697d8800e4cf56f0c3d493924db"),
            hex!("1c584e1e7d3056380a55cd818923e2624c63cabea891132db922d7bcc8861987"),
            hex!("d35b4267024e233741bea52bf38f2e241d716989e9d9688fab0f91d487c2aa54"),
            hex!("ef2072fc683ba12d2ec2f90d0b3422ccd4239f395f55c79489b0d7f90ef8d1bc"),
            hex!("cacb1e09595fd7be7bb18c75188728e8eaf7d87211fb66e40cb4564f1d7305fc"),
            hex!("910a34c4d9dd295431e2412d98c67335f25711f2771d7f7e527309492a58ff81"),
            hex!("445ef107ae6bc284343262873e323146932248280d5b29306ef74de8bd6e828d"),
            hex!("b4e884814be9f3fbf6bc61a33f906484f2b80afe8cb32e722af43f43f40ee42c"),
            hex!("4f55bf32ef8ae87b7f895e1804cdecebd98aee992b30d6e53902d895d32ecdac"),
            hex!("99a23bb3a066851c33a6c4ac3d9e34de2a1423f108fc16a4cce4d0897cf17b81"),
            hex!("1215cbe3320739c6f662669e4f45acd1b461c889e8edf13ccafb6e590835e3de"),
            hex!("40ccf59cd2500b796ddeff843136bf23bf4d2b71c084f5f0cf6deae557c46170"),
            hex!("49d944f737f8b75acc2308a6f7baa883f6bb0816ca5b65cc88f6068289693cb2"),
            hex!("bb049f04ffdc565c544b1441bc2a5db1c2eaebf09a2ba4920cf6fb0c32f0c522"),
            hex!("0328cd4605f4aa4f0f656770c0e72ccb37b427672ad6362c5d4abb1de7ac237d"),
            hex!("01c722426ea09132bfaecf8c5d50f8523cdd7ab5c67b596adef4a6fdb0977444"),
            hex!("21265890d0fe6042d92bf2b0644ebd54fb472e5ad6dfe09c648f0230155edce4"),
            hex!("58366bfb16fc60ff446ee89401a41ac7eb1800d0b8a3a749abc1a84db0b5bdc9"),
            hex!("1ebf89b756fbaba4d2321e80bf50426f8753489770c5aa60bfd5e86eaa4ce35c"),
            hex!("6ebebcdd5a52d80af6653d627307ec8349f24011df8fee4cdc4b0df1e9356ebc"),
            hex!("37ca510de62da54011bd24e8b585d0f7df6ecfb019aa83ba9869386f11011b4b"),
            hex!("2953b4e4035f3b4f03df09ab6fa623f03d6b50f656de6d17a550aea26b3d1b4e"),
            hex!("624c236f45995d1a3f0382a953762b454d1342a0d0354af0f7a5478a4dda4e9d"),
            hex!("d73e543b6a5a336581600608a55f66d86125e7ad9d5dbd54c509d07d71bd3cc1"),
            hex!("360981d0e5d51df11fb86d118430c09826c1ee116fa259c00268b0b50670aa80"),
            hex!("3e7b2afab20c0bfa2024d5418f37188d64ee695d268c7fef6075db2cbb100d79"),
            hex!("b1eda0998f95fed1946dd9813c2367c3d4c4a9f9a096a066fd335d8a28adde9e"),
            hex!("fa2b5540043c74c65649c61cc2af795963152fec6c72362c69b7ff466230b6fb"),
            hex!("b398426a304b57a5000fc46d5371eaffd10e44b2e54f75924cf4ee616a7d2716"),
            hex!("f85a93dfc9b5a5f3649cb9eec337c507a4c073f7b1b114a6bfcc687cf45740a5"),
            hex!("0030b09e83d8f9330f121aa76ff8a88a09a2cf1b161cb9b07c9560f01b15ab78"),
            hex!("ead24da34ec7878b4b87916008c9723cd3544d048c067863867034b72a0047ed"),
            hex!("74d7874e9a5acdf0452ce815b98d61493258a7e2e3dc2377fbd9b73ff4cf4d75"),
            hex!("246d82d3b826dad2fb1546df980a19a6afe62a1797a0513f8c7541eeaa79f0c7"),
            hex!("40a72643734680ad0aa4b6b8988ff4cd2b95aff93de927f1976129ac2abfcbd3"),
            hex!("12e6739b55441ea1cdf2523430a9404d40f6a632f2147a477a0e2dfb6dde3825"),
            hex!("ebb367273898d9e1c97e323d4b792a59739ebb4e66767673045e1a4288115151"),
            hex!("6863d5a3f5c9373863f8fe951f27d4becad824c2e7b8033037c4360715c2fca2"),
            hex!("decd54f8d3a3d4247cd7d6b078fe3c6c0dffdba1a3f7903cc9f597acb1e3df3f"),
            hex!("276b80e302c4ac04baaeb5b6b3b82e63e6aa05382cf23a9ee4766d70aa9a2b7a"),
            hex!("2b480fd21955dab194a0227eb7dd5078eb2a17079754d782dfe4c73b1eff955f"),
            hex!("048881a383fa262d8d24ade8079c3c32b8bbd66a30b4c0ee225ecbf6459e699a"),
            hex!("9eb162aeaf6a358a2a39d339cb97b85deafc64a9f4531fda818950de254c4109"),
            hex!("e9239b3ba64492f8bfc42a53bb310fb1f8b8ff00c47f3eb3cdeb395a797658c2"),
            hex!("8bf694f65f070da4ec8ec792908813fd811e0203d1b6445b854bbf40b1142ef4"),
            hex!("c47c23a922e0edf2d44e1c1e36832b5ac5d98900f2567c5dfc35525fa5c3a6f7"),
            hex!("1ee99a4d65dc4fd34e3424818c65c5844b258b76ff27f96ad155533e3b59e4ba"),
            hex!("0198e75a02419da99adf8d8b3d6a78f934935354251cc4aed4f98df034213d75"),
            hex!("85571fe4f735d95ede20e6b204d0c93e444b1d1f70bd0679e0b562eabbe6e2a3"),
            hex!("cd88985a6eb9669a7e67388968a677590715b8c8eb8fc9ca34747ac8dd8fff02"),
            hex!("ff174846eff1145ffe987fd0b295a25b998449847aceeb14f90aa4a240434e1f"),
            hex!("5cfb508f9929718da7a6483d6ec886f31cfa19a8e1285de56019f1273299508f"),
            hex!("ee6ab2fcf31a2e14194cb92b6da20f2949d0502ea688671c43ffb34ad343e084"),
            hex!("0ebd80d47384c65cc77f1f26e98ba8674eb8e74018bb08eadc08efb440ad19c8"),
            hex!("225dcf27915399aab44dbbc9a509682c1ad446b8eefc3cbdd22ce24c2eaa9178"),
            hex!("f0b1759555f2cc14dad2eea4c8d542190f44c3666ceba22a0344d1a33b6d81d4"),
            hex!("700f62b2d16425ef1f02f21ecc3393e7a759d4cfb9a5cb9ca52d7619cb80bbc7"),
            hex!("0c85ed5b5f22acd8eb4abef105d049d0453c6509ace715e097a399237d58b691"),
            hex!("d38493a94e8fa6e0b98ca4842bb8e335614996800ccddeb29cf444624a42511c"),
            hex!("ac6068d7e895630d4f5b5a73d9b98ad5a6b72b31a1b9a8854b4f3898d4adc542"),
            hex!("c7ebbe81a30fbad9ce087ff9e6792341473fa6f0ee9cf8704ec87c630909daaa"),
            hex!("c6edb1b339cc28a8230d0ca91f03674eb93e9396829325fdc1c56033f58cf658"),
            hex!("fe104ac27da766f50aa4ef116c00b7d96e2f439a7b51f3e8f08a610b9901ab98"),
            hex!("f49eef885e45366a0645299be1a9299b275b72757dae4aee7b319a4582600ac2"),
            hex!("b9b01392e35ab25653f6199294a78b7485002a60be44603c30a8e9f68a37e4af"),
            hex!("6f4aa091896384f2d04c33c937174af53946dda0597174ac6c4e791ce6dc6bf2"),
            hex!("6c7930bbc5825ecd87e20724a03aa503ee2c7ac79dcfc6e719793caf8240d3d3"),
            hex!("dd8fd99d3528e412593755534ef6333965619ad9c78e356513333f1458224b30"),
            hex!("1f6bbd163ae3edb41a0cc40d466e35d1ef3366b64b768a9c64d3025714c337ca"),
            hex!("66c511f4b33f01e052cc51050d5741de6859ddff4329f7a77559de71c593435c"),
            hex!("009cedb10ac050fa833ea1cc07f3bf8900d9916c24e3afa40f47b800b1115516"),
            hex!("0586a5f692a01a97cc489cf2343de768fc999b1ce5500904a8c8a656c60710ee"),
            hex!("85e7870ac2e9c116aa5b64bd0e3e5f95bc31b8abb7d83e4d54bffe08c1ec2c5d"),
            hex!("225a3db38630adfd58e7c29b74167d530811824ddc7b31ac9598336dbf902ca8"),
            hex!("e9ed92feed0234a638b8c700327571c245ceed153f9ae1aa7577a570ca65d4dd"),
            hex!("fdbc2ddaeb3ccd9f98343d9e6134de44e8a4f10964ba1929825036ec4a794e1a"),
            hex!("ad2adb22f9469609744e32b6fd38df6b71dc6c4fce017f5aef3a4803042b1eab"),
            hex!("671a9efd6d9f9d39c4f2507e96ffb6ab79a6b8d018880ebaeb923f7ac2190a9f"),
            hex!("5e33603b6fc04e71c5bb9037922c3b82dbe97fee8bf7ad1141e63d9be1e37f07"),
            hex!("a2fb6e0a9a429d7ad2943f8d6f5c5aac52a5ac97ba34b08467e064fc42270a9c"),
            hex!("69aeea06116829ae6c1bb088352980bfe670e97d3e1881936eab07ebd444e264"),
            hex!("6bfbdbb3df1d985bb274e56f5f24dc4f5a8c9cfdf66d42a167098169aeb645b7"),
            hex!("445ab27a6948995c9bbb4c90ba726914712e3e5e617aa1b6155571b46eacad99"),
            hex!("8d1a6d1e0e49bd475c99e33d0d76e6c632da6ebb9b4cf69fafa10cd54e7444ed"),
            hex!("6005098a57041edb8a8ab7efb312be0219e8c82222982a3ad8d1cfb99efedc21"),
            hex!("ebe1f6f2c431b8aa7ea4c3e00308f5b3e72d03ebee85dcf97f6072969e8b6e3a"),
            hex!("fa554ed4ab986d77966d9bde88df9f176cb1b50b18d333c0cdc37e97134619e6"),
            hex!("686b8b50812d592e3e7986fdeca248dc99860a13b1ee2b4b12539817323a17cf"),
            hex!("8690fd5fdde3653af7cfe50e4f7e4bad565cee682cfc42b7f28a00e5585247cd"),
            hex!("9fd492ae93e3f9d558656b6523212974325b43555f39687f1603268aead6e549"),
            hex!("dc71216a7e5193f8ae3ee589b7f8941b91a5e6b617563e68a0835180dfff2224"),
        ]
    }
}
