#include <stdio.h>
#include <iostream>

#include <boost/optional.hpp>
#include <boost/foreach.hpp>
#include <boost/format.hpp>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>

#include "Note.h"

using namespace libsnark;
using namespace libff;
using namespace std;

#include "circuit/gadget.tcc"

#define DEBUG 0

// 生成proof
template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_claim_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                    const Note& notes,
                                                                    const NoteC& notec,
                                                                    uint256 cmtS,
                                                                    uint256 cmtC,
                                                                    uint64_t L,
                                                                    uint64_t N
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;  // 定义原始模型，该模型包含constraint_system成员变量
    claim_gadget<FieldT> claim(pb); // 构造新模型
    claim.generate_r1cs_constraints(); // 生成约束

    claim.generate_r1cs_witness( notes, notec, cmtS, cmtC, L, N); // 为新模型的参数生成证明

    cout << "pb.is_satisfied() is " << pb.is_satisfied() << endl;

    if (!pb.is_satisfied()) { // 三元组R1CS是否满足  < A , X > * < B , X > = < C , X >
        return boost::none;
    }

    // 调用libsnark库中生成proof的函数
    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

// 验证proof
template<typename ppzksnark_ppT>
bool verify_claim_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                    r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                    const uint256& cmtS,
                    const uint256& cmtC,
                    uint64_t L,
                    uint64_t N
                  )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = claim_gadget<FieldT>::witness_map(
        cmtS,
        cmtC,
        L,
        N
    ); 

    // 调用libsnark库中验证proof的函数
    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}

template<typename ppzksnark_ppT>
void PrintProof(r1cs_ppzksnark_proof<ppzksnark_ppT> proof)
{
    printf("================== Print proof ==================================\n");
    //printf("proof is %x\n", *proof);
    std::cout << "send proof:\n";

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
bool test_claim_gadget_with_instance(
                            uint64_t value_s,   //amount
                            uint64_t value_c,   //va
                            uint64_t L,         //L
                            uint64_t N          //N
                        )
{
    std::cout << "generate parameter..."<< endl;
    uint256 sn_s = uint256S("123");//random_uint256();
    uint256 r_s = uint256S("123");//random_uint256();
    Note notes = Note(value_s, sn_s, r_s);
    uint256 cmtS = notes.cm();
    //uint256 cmtS_w = uint256S("345");

    uint256 r_c = uint256S("123");//random_uint256();
    NoteC notec = NoteC(value_c, r_c);
    uint256 cmtC = notec.cm();

    
    typedef libff::Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    claim_gadget<FieldT> claim(pb);
    std::cout << "generate r1cs constraints..."<<endl;
    claim.generate_r1cs_constraints();// 生成约束

    // check constraints
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    
    // key pair generation
    r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
   
    // 生成proof
    cout << "Trying to generate proof..." << endl;

    auto proof = generate_claim_proof<default_r1cs_ppzksnark_pp>(keypair.pk, 
                                                            notes,
                                                            notec,
                                                            cmtS,
                                                            cmtC,
                                                            L,
                                                            N
                                                            );

    // 验证proof
    if (!proof) {
        printf("generate claim proof fail!!!\n");
        return false;
    } else {
        bool result = verify_claim_proof(keypair.vk, 
                                   *proof, 
                                   cmtS,
                                   cmtC,
                                   L,
                                   N
                                   );

        if (!result){
            cout << "Verifying claim proof unsuccessfully!!!" << endl;
        } else {
            cout << "Verifying claim proof successfully!!!" << endl;
        }
        
        return result;
    }
}

int main () {
    default_r1cs_ppzksnark_pp::init_public_params();

    libff::print_header("#             testing claim gadget");

    uint64_t value_s = uint64_t(600);
    uint64_t value_c = uint64_t(1000);
    uint64_t L = uint64_t(6);
    uint64_t N = uint64_t(10);


    test_claim_gadget_with_instance<default_r1cs_ppzksnark_pp>(value_s, value_c, L, N);

    // Note. cmake can not compile the assert()  --Agzs
    
    return 0;
}

