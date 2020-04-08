/*****************************************************
 * note_gadget_with_packing for packing value, value_old and value_s
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_packing_and_ADD : public gadget<FieldT> { // 基类
public:
    pb_variable_array<FieldT> value_s; // 64位的value，待操作的账户余额 refund_i
    pb_variable<FieldT> value_s_packed;

    std::shared_ptr<digest_variable<FieldT>> sn_s; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_s; // 256位的随机数r

    pb_variable_array<FieldT> value_old; // 64位的value，操作前的账户余额
    pb_variable<FieldT> value_old_packed;

    std::shared_ptr<digest_variable<FieldT>> sn_old; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_old; // 256位的随机数r

    pb_variable_array<FieldT> value; // 64位的value, 操作后的账户余额，也是当前最新的账户余额
    pb_variable<FieldT> value_packed;

    std::shared_ptr<digest_variable<FieldT>> sn; // 256位的随机数serial number    
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    pb_variable_array<FieldT> fees; // 64位的value
    pb_variable<FieldT> fees_packed;

    pb_variable_array<FieldT> cost; // 64位的value
    pb_variable<FieldT> cost_packed;

    note_gadget_with_packing_and_ADD(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &sn_s,
        std::shared_ptr<digest_variable<FieldT>> &r_s,
        pb_variable_array<FieldT> &value_old,
        std::shared_ptr<digest_variable<FieldT>> &sn_old,
        std::shared_ptr<digest_variable<FieldT>> &r_old,
        pb_variable_array<FieldT> &value,
        std::shared_ptr<digest_variable<FieldT>> &sn,
        std::shared_ptr<digest_variable<FieldT>> &r,
        pb_variable_array<FieldT> &fees,
        pb_variable_array<FieldT> &cost
    ) : gadget<FieldT>(pb), 
        value_s(value_s), 
        sn_s(sn_s),
        r_s(r_s),
        value_old(value_old), 
        sn_old(sn_old), 
        r_old(r_old),
        value(value), 
        sn(sn),
        r(r),
        fees(fees),
        cost(cost)
    {
        value_s_packed.allocate(pb, "value_s_packed");
        value_old_packed.allocate(pb, "value_old_packed");
        value_packed.allocate(pb, "value_packed");
        fees_packed.allocate(pb, "fees_packed");
        cost_packed.allocate(pb, "cost_packed");
    }

    void generate_r1cs_constraints() { // const Note& note

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
                value_old[i],
                "boolean_value_old"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                value[i],
                "boolean_value"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                cost[i],
                "boolean_cost"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                fees[i],
                "boolean_fees"
            );
        }

        // 1 * (value_old + value_s(refund_i)) = this->value 
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (this->value_old_packed + this->value_s_packed), this->value_packed),
                                 FMT(this->annotation_prefix, " equal"));
        // 1 *  (fees- cost_i) = refund_i
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (this->fees_packed - this->cost_packed), this->value_s_packed),
                                 FMT(this->annotation_prefix, " equal"));
        
        sn_s->generate_r1cs_constraints(); // 随机数的约束
        r_s->generate_r1cs_constraints(); // 随机数的约束

        sn_old->generate_r1cs_constraints(); // 随机数的约束
        r_old->generate_r1cs_constraints(); // 随机数的约束

        sn->generate_r1cs_constraints(); // 随机数的约束
        r->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const Note& note_s, const Note& note_old, const Note& note,uint64_t fees_data,uint64_t cost_data) { // 为变量生成约束
        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(note_s.value));
        this->pb.lc_val(value_s_packed) = value_s.get_field_element_from_bits_by_order(this->pb);

        value_old.fill_with_bits(this->pb, uint64_to_bool_vector(note_old.value));
        this->pb.lc_val(value_old_packed) = value_old.get_field_element_from_bits_by_order(this->pb);

        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value));
        this->pb.lc_val(value_packed) = value.get_field_element_from_bits_by_order(this->pb);
        
        sn_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_s.sn));
        r_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_s.r));

        sn_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_old.sn));
        r_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note_old.r));

        sn->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.sn));
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(note.r));

        fees.fill_with_bits(this->pb, uint64_to_bool_vector(fees_data));
        this->pb.lc_val(fees_packed) = fees.get_field_element_from_bits_by_order(this->pb);

        cost.fill_with_bits(this->pb, uint64_to_bool_vector(cost_data));
        this->pb.lc_val(cost_packed) = cost.get_field_element_from_bits_by_order(this->pb);

    }
};