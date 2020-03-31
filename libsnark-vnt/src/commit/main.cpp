#include <stdio.h>
#include <iostream>

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>
#include <boost/array.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp"

#include "Note.h"
#include "IncrementalMerkleTree.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;
using namespace libvnt;

#include "circuit/gadget.tcc"

#define DEBUG 0

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    const NoteS& note_s,
                                                                    const NoteC& note_c,
                                                                    uint256 cmtS,
                                                                    uint256 cmtC,
                                                                    const uint256& rt,
                                                                     const MerklePath& path
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    commit_gadget<FieldT> commit(pb); // 构造新模型
    commit.generate_r1cs_constraints(); // 生成约束

    commit.generate_r1cs_witness(note_s, note_c, cmtS, cmtC, rt, path); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                    r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                    const uint256& rt,
                    const uint256& sn_s,
                    const uint256& cmtC            )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = commit_gadget<FieldT>::witness_map(
        rt,
        sn_s,
        cmtC
    ); 

    // 调用libsnark库中验证proof的函数
    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename ppzksnark_ppT>
void PrintProof(r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    printf("================== Print proof ==================================\n");
    //printf("proof is %x\n", *proof);
    std::cout << "commit proof:\n";

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_A: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_A.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_A.h << endl;

    std::cout << "\n knowledge_commitment<G2<ppT>, G1<ppT> > g_B: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_B.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_B.h << endl;

    std::cout << "\n knowledge_commitment<G1<ppT>, G1<ppT> > g_C: ";
    std::cout << "\n   knowledge_commitment.g: \n     " << proof.g_C.g;
    std::cout << "\n   knowledge_commitment.h: \n     " << proof.g_C.h << endl;


    std::cout << "\n G1<ppT> g_H: " << proof.g_H << endl;
    std::cout << "\n G1<ppT> g_K: " << proof.g_K << endl;
    printf("=================================================================\n");
}

template<typename ppzksnark_ppT> //--Agzs
bool test_commit_gadget_with_instance(
                            uint64_t value_s
                        )
{
   
    uint256 sn_s = uint256S("123");//random_uint256();
    uint256 r_s = uint256S("123");//random_uint256();
    NoteS note_s = NoteS(value_s, sn_s, r_s);
    uint256 cmtS = note_s.cm();

    uint256 r_c = uint256S("123");//random_uint256();
    NoteC note_c = NoteC(value_s, r_c);
    uint256 cmtC = note_c.cm();

    boost::array<uint256, 16> commitments; //16个cmts
    //std::vector<boost::optional<uint256>>& commitments;
    
    const char *str[] = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
                    "11", "12", "13", "14", "15", "16"};
    commitments[9] = cmtS;
    cout << "cmtS = 0x" << cmtS.ToString() << endl;
    for (size_t i = 0; i < 16; i++) {
        if(i == 9) {
            //cout << "commitments[" << i << "] = 0x" << commitments[i].ToString() << endl;
            continue;
        }
        //const char *ch = str[i];
        commitments[i] = uint256S(str[i]);
        //cout << "commitments[" << i << "] = 0x" << commitments[i].ToString() << endl;
    }

    ZCIncrementalMerkleTree tree;
    assert(tree.root() == ZCIncrementalMerkleTree::empty_root());
    
    ZCIncrementalWitness wit = tree.witness(); //初始化witness
    bool find_cmtS = false;
    for (size_t i = 0; i < 16; i++) {
        if (find_cmtS) {
            wit.append(commitments[i]);
        } else {
            /********************************************
             * 如果删除else分支，
             * 将tree.append(commitments[i])放到for循环体中，
             * 最终得到的rt == wit.root() == tree.root()
             *********************************************/
            tree.append(commitments[i]);
        }

        if (commitments[i] == cmtS) {
            //在要证明的叶子节点添加到tree后，才算真正初始化wit，下面的root和path才会正确。
            wit = tree.witness(); 
            find_cmtS = true;
        } 
    }

    auto path = wit.path();
    uint256 rt = wit.root();

    cout << "tree.root = 0x" << tree.root().ToString() << endl;
    cout << "wit.root = 0x" << wit.root().ToString() << endl;
   
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    commit_gadget<FieldT> commit(pb);
    commit.generate_r1cs_constraints();// 生成约束

    // check conatraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

    // 生成proof
    cout << "Trying to generate proof..." << endl;

    auto proof = generate_proof<default_r1cs_ppzksnark_pp>(keypair.pk, 
                                                            note_s,
                                                            note_c,
                                                            cmtS,
                                                            cmtC,
                                                            rt, 
                                                            path 
                                                            );

    // verify proof
    if (!proof) {
        printf("generate commit proof fail!!!\n");
        return false;
    } else {
        PrintProof(*proof);
        
        bool result = verify_proof(keypair.vk, 
                                    *proof, 
                                    rt, 
                                    sn_s,
                                    cmtC
                                   );

        printf("verify result = %d\n", result);
         
        if (!result){
            cout << "Verifying commit proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying commit proof successfully!!!" << endl;
        }
        
        return result;
    }
}

int main () {
    default_r1cs_ppzksnark_pp::init_public_params();

    libff::print_header("#             testing commit gadget");

    uint64_t value_s = uint64_t(9);

    test_commit_gadget_with_instance<default_r1cs_ppzksnark_pp>(value_s);

    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

