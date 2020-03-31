/*****************************************************
 * note_gadget_with_sub_and_comparison for packing value_old, value_s and value
 * value == value_old - value_s(转化金额)
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_sub_and_comparison : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget
public: 
    //cmt_old   
    pb_variable_array<FieldT> value_old; // 64位的value，操作前的账户余额
    pb_variable<FieldT> value_old_packed;
    std::shared_ptr<digest_variable<FieldT>> sn_old; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_old; // 256位的随机数r
    //cmt_s
    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额
    pb_variable<FieldT> value_s_packed;
    std::shared_ptr<digest_variable<FieldT>> sn_s; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_s; // 256位的随机数r
    //cmt_new
    pb_variable_array<FieldT> value; // 64位的value, 操作后的账户余额，也是当前最新的账户余额
    pb_variable<FieldT> value_packed;
    std::shared_ptr<digest_variable<FieldT>> sn; // 256位的随机数serial number    
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    std::shared_ptr<less_comparison_gadget<FieldT> > less_cmp; //comparison_gadget

    note_gadget_with_sub_and_comparison(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value_old,
        std::shared_ptr<digest_variable<FieldT>> &sn_old,
        std::shared_ptr<digest_variable<FieldT>> &r_old,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &sn_s,
        std::shared_ptr<digest_variable<FieldT>> &r_s,
        pb_variable_array<FieldT> &value,
        std::shared_ptr<digest_variable<FieldT>> &sn,
        std::shared_ptr<digest_variable<FieldT>> &r
    ) : gadget<FieldT>(pb), 
        value_old(value_old), 
        sn_old(sn_old), 
        r_old(r_old),
        value_s(value_s), 
        sn_s(sn_s),
        r_s(r_s),
        value(value),
        sn(sn),
        r(r)
    {        
        value_old_packed.allocate(pb, "value_old_packed");
        value_s_packed.allocate(pb, "value_s_packed");
        value_packed.allocate(pb, "value_packed");

        less_cmp.reset(new less_comparison_gadget<FieldT>(
            pb, 
            this->value_s_packed, 
            this->value_old_packed,
            FMT(this->annotation_prefix,"less_cmp")));
    }

    void generate_r1cs_constraints() { // const Note& note

        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_old[i],
                "boolean_value_old"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value_s[i],
                "boolean_value_s"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value[i],
                "boolean_value"
            );
        }

        sn_old->generate_r1cs_constraints(); // 随机数的约束
        r_old->generate_r1cs_constraints(); // 随机数的约束
        sn_s->generate_r1cs_constraints(); // 随机数的约束
        r_s->generate_r1cs_constraints(); // 随机数的约束
        sn->generate_r1cs_constraints(); // 随机数的约束
        r->generate_r1cs_constraints(); // 随机数的约束

        // 1 * (value_old - value_s) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (this->value_old_packed - this->value_s_packed), this->value_packed),
                                 FMT(this->annotation_prefix, " equal"));

        less_cmp->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const Note& note_old, const Note& notes, const Note& note) { // 变量转化为证据        
        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(note_old.value));
        this->pb.lc_val(value_old_packed) = value_old.get_field_element_from_bits_by_order(this->pb);

        sn_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_old.sn));
        r_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_old.r));

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(notes.value));
        this->pb.lc_val(value_s_packed) = value_s.get_field_element_from_bits_by_order(this->pb);

        sn_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.sn));
        r_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.r));

        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
        this->pb.lc_val(value_packed) = value.get_field_element_from_bits_by_order(this->pb);
        
        sn->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.sn));
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));

        less_cmp->generate_r1cs_witness();
    }
};