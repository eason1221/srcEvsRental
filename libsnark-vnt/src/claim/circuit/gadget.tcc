#include "utils.tcc"
#include "note.tcc"
#include "commitment.tcc"

/************************************************************************
 * 模块整合，主要包括验证proof时所需要的publicData的输入
 ************************************************************************
 * sha256_one_block_gadget, sha256_two_block_gadget
 ************************************************************************
 * sha256(data+padding), 512bits < data.size() < 1024-64-1bits
 * **********************************************************************
 * publicData: cmtS,cmtt , dist, subdist  
 * privateData: value_s(cost), sn_s, r_s ,subcost, r
 * **********************************************************************/
template<typename FieldT>
class claim_gadget : public gadget<FieldT> {
public:
    // Verifier inputs 验证者输入
    pb_variable_array<FieldT> zk_packed_inputs; // 合并为十进制
    pb_variable_array<FieldT> zk_unpacked_inputs; // 拆分为二进制
    std::shared_ptr<multipacking_gadget<FieldT>> unpacker; // 二进制转十进制转换器

    // cmtS = sha256(value_s, sn_s, r_s)
    pb_variable_array<FieldT> value_s;                //cost_i,单个user需要支付的费用
    std::shared_ptr<digest_variable<FieldT>> sn_s;    // 256bits serial number associsated with a balance transferred between two accounts
    std::shared_ptr<digest_variable<FieldT>> r_s;     // 256bits random number

    // note gadget and subtraction constraint
    std::shared_ptr<note_gadget_with_packing<FieldT>> note;

    // new commitment with sha256_two_block_gadget
    std::shared_ptr<digest_variable<FieldT>> cmtS; // cm
    std::shared_ptr<sha256_two_block_gadget<FieldT>> commit_to_input_cmt_s; // note_commitment

    //cmtt
    std::shared_ptr<digest_variable<FieldT>> cmtt; // cm
    std::shared_ptr<sha256_one_block_gadget<FieldT>> commit_to_input_cmt_t; // note_commitment
    
    //parameter
    pb_variable_array<FieldT> subcost;
    std::shared_ptr<digest_variable<FieldT>> r;//
    pb_variable_array<FieldT> subdist;
    pb_variable_array<FieldT> dist;

    pb_variable<FieldT> ZERO;

    claim_gadget(
        protoboard<FieldT>& pb
    ) : gadget<FieldT>(pb) {
        // Verification
        {
            // The verification inputs are all bit-strings of various
            // lengths (256-bit digests and 64-bit integers) and so we
            // pack them into as few field elements as possible. (The
            // more verification inputs you have, the more expensive
            // verification is.)
            zk_packed_inputs.allocate(pb, verifying_field_element_size()); 
            this->pb.set_input_sizes(verifying_field_element_size());

            //!验证proof需要输入的参数，即公开参数
            alloc_uint256(zk_unpacked_inputs, cmtS);
            alloc_uint256(zk_unpacked_inputs, cmtt);
            alloc_uint64(zk_unpacked_inputs, this->subdist);
            alloc_uint64(zk_unpacked_inputs, this->dist);
            

            assert(zk_unpacked_inputs.size() == verifying_input_bit_size()); // 判定输入长度

            // This gadget will ensure that all of the inputs we provide are
            // boolean constrained. 布尔约束 <=> 比特位, 打包
            unpacker.reset(new multipacking_gadget<FieldT>(
                pb,
                zk_unpacked_inputs,
                zk_packed_inputs,
                FieldT::capacity(),
                "unpacker"
            ));
        }

        ZERO.allocate(this->pb, FMT(this->annotation_prefix, "zero"));
        //!不需要验证proof输入的参数 但是需要重新reset参数---即隐私参数
        value_s.allocate(pb, 64);
        sn_s.reset(new digest_variable<FieldT>(pb, 256, "serial number"));
        r_s.reset(new digest_variable<FieldT>(pb, 256, "random number"));
        //
        subcost.allocate(pb, 64);
        r.reset(new digest_variable<FieldT>(pb, 256, "random number"));
       
        note.reset(new note_gadget_with_packing<FieldT>(
            pb,
            value_s, 
            sn_s,
            r_s,
            subcost,
            r,//
            subdist,
            dist
        ));

        commit_to_input_cmt_s.reset(new sha256_two_block_gadget<FieldT>( 
            pb,
            ZERO,
            value_s,       // 64bits value
            sn_s->bits,    // 256bits serial number
            r_s->bits,     // 256bits random number
            cmtS
        ));
        //
        commit_to_input_cmt_t.reset(new sha256_one_block_gadget<FieldT>( 
            pb,
            ZERO,
            subcost,       // 64bits value
            r->bits,     // 256bits random number
            cmtt
        ));
    }

    // 约束函数，为commitment_with_add_and_less_gadget的变量生成约束
    void generate_r1cs_constraints() { 
        // The true passed here ensures all the inputs are boolean constrained.
        unpacker->generate_r1cs_constraints(true);

        note->generate_r1cs_constraints();
        // Constrain `ZERO`
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");
        // TODO: These constraints may not be necessary if SHA256
        // already boolean constrains its outputs.
        cmtS->generate_r1cs_constraints();
        commit_to_input_cmt_s->generate_r1cs_constraints();

        //
        cmtt->generate_r1cs_constraints();
        commit_to_input_cmt_t->generate_r1cs_constraints();
    }

    // 证据函数，为commitment_with_add_and_less_gadget的变量生成证据
    void generate_r1cs_witness( 
        const Note& note_s, 
        const NoteC& note_cmtt,
        uint256 cmtS_data,
        uint256 cmtt_data,
        uint64_t dist_data,
        uint64_t subdist_data
    ) {

        note->generate_r1cs_witness(note_s, note_cmtt,dist_data,subdist_data);

        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        // Witness the commitment of the input note
        commit_to_input_cmt_s->generate_r1cs_witness();
        commit_to_input_cmt_t->generate_r1cs_witness();
        // [SANITY CHECK] Ensure the commitment is
        // valid.
        cmtS->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(cmtS_data)
        );
        cmtt->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(cmtt_data)
        );
        // This happens last, because only by now are all the verifier inputs resolved.
        unpacker->generate_r1cs_witness_from_bits();
    }

    // 将bit形式的私密输入 打包转换为 域上的元素|验证proof输入
    static r1cs_primary_input<FieldT> witness_map(
        const uint256& cmtS,
        const uint256& cmtt,
        uint64_t subdist,
        uint64_t dist

    ) {
        std::vector<bool> verify_inputs;
        
        insert_uint256(verify_inputs, cmtS);
        insert_uint256(verify_inputs, cmtt);//
        insert_uint64(verify_inputs, subdist);
        insert_uint64(verify_inputs, dist);

        assert(verify_inputs.size() == verifying_input_bit_size());
        auto verify_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
        assert(verify_field_elements.size() == verifying_field_element_size());
        return verify_field_elements;
    }

    // 计算验证输入元素的bit大小
    static size_t verifying_input_bit_size() {
        size_t acc = 0;

        acc += 256; // cmtS
        acc += 256; // cmtt
        acc += 64;  // subdist
        acc += 64;  // dist
        return acc;
    }

    // 计算域上元素的组数
    static size_t verifying_field_element_size() {
        return div_ceil(verifying_input_bit_size(), FieldT::capacity());
    }

    // 分配空间，打包追加
    void alloc_uint256(
        pb_variable_array<FieldT>& packed_into,
        std::shared_ptr<digest_variable<FieldT>>& var
    ) {
        var.reset(new digest_variable<FieldT>(this->pb, 256, ""));
        packed_into.insert(packed_into.end(), var->bits.begin(), var->bits.end());
    }

    // 分配空间，打包追加
    void alloc_uint64(
        pb_variable_array<FieldT>& packed_into,
        pb_variable_array<FieldT>& integer
    ) {
        integer.allocate(this->pb, 64, "");
        packed_into.insert(packed_into.end(), integer.begin(), integer.end());
    }
};