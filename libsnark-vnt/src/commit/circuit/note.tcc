/*****************************************************
 * note_gadget for packing value_s
 * ***************************************************/
template<typename FieldT>
class note_three_gadget : public gadget<FieldT> { // 基类
public:
    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_s_packed;

    std::shared_ptr<digest_variable<FieldT>> sn_s; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_s; // 256位的随机数r


    note_three_gadget(
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

    void generate_r1cs_witness(const NoteS& note_s) { // 为变量生成约束
        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(note_s.value));
        this->pb.lc_val(value_s_packed) = value_s.get_field_element_from_bits_by_order(this->pb);
        
        sn_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_s.sn_s));
        r_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_s.r));
    }
};

/*****************************************************
 * note_gadget for packing value_c
 * ***************************************************/
template<typename FieldT>
class note_two_gadget : public gadget<FieldT> { // 基类
public:
    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_s_packed;
    std::shared_ptr<digest_variable<FieldT>> r_s; // 256位的随机数r

    note_two_gadget(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &r_s
    ) : gadget<FieldT>(pb), 
        value_s(value_s), 
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
        
        r_s->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const NoteC& note_s) { // 为变量生成约束
        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(note_s.value));
        this->pb.lc_val(value_s_packed) = value_s.get_field_element_from_bits_by_order(this->pb);
        
        r_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_s.r));
    }
};