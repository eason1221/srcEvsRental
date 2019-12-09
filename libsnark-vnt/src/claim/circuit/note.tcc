/*****************************************************
 * note_gadget_with_packing for packing value_old and value_s
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_packing : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget
public:    
 
    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_s_packed;

    std::shared_ptr<digest_variable<FieldT>> sn_s; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_s; // 256位的随机数r

    note_gadget_with_packing(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &sn_s,
        std::shared_ptr<digest_variable<FieldT>> &r_s
    ) : gadget<FieldT>(pb), 
        value_s(value_s), 
        sn_s(sn_s),
        r_s(r_s)
    {        
        value_s_packed.allocate(pb, "value_s_packed");
    }

    void generate_r1cs_constraints() { // const Note& note

        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_s[i],
                "boolean_value_s"
            );
        }

        sn_s->generate_r1cs_constraints(); // 随机数的约束
        r_s->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const Note& notes) { // 为变量生成约束        

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(notes.value));
        this->pb.lc_val(value_s_packed) = value_s.get_field_element_from_bits_by_order(this->pb);

        sn_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.sn));
        r_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.r));
    }
};