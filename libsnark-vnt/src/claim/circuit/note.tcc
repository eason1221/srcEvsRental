/*****************************************************
 * note_gadget_with_packing for packing value_s
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_packing : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget
public:    
 
    pb_variable_array<FieldT> value_s; // 64位的value，即单个user需要支付的费用 cost_i=cost×dist_i/(Σdist_i)
    pb_variable<FieldT> value_s_packed;
    std::shared_ptr<digest_variable<FieldT>> sn_s; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_s; // 256位的随机数r

    pb_variable_array<FieldT> subcost; // 总支付租车费用 = cost
    pb_variable<FieldT> subcost_packed;
    //
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    pb_variable_array<FieldT> subdist; // 总租车里程 = Σdist_i
    pb_variable<FieldT> subdist_packed;

    pb_variable_array<FieldT> dist; // 单个user租车里程 = dist_i
    pb_variable<FieldT> dist_packed;

    pb_variable_array<FieldT> fees; // 租车所用押金fees
    pb_variable<FieldT> fees_packed;

    pb_variable_array<FieldT> refundi; // user剩余回款金额refund_i
    pb_variable<FieldT> refundi_packed;

    pb_variable_array<FieldT> tmp; // 中间值
    pb_variable<FieldT> tmp_packed;

    note_gadget_with_packing(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT> &value_s,
        std::shared_ptr<digest_variable<FieldT>> &sn_s,
        std::shared_ptr<digest_variable<FieldT>> &r_s,
        pb_variable_array<FieldT> &subcost,
        std::shared_ptr<digest_variable<FieldT>> &r,
        pb_variable_array<FieldT> &subdist,
        pb_variable_array<FieldT> &dist,
        pb_variable_array<FieldT> &fees,
        pb_variable_array<FieldT> &refundi
    ) : gadget<FieldT>(pb), 
        value_s(value_s), 
        sn_s(sn_s),
        r_s(r_s),
        subcost(subcost),
        r(r),
        subdist(subdist),
        dist(dist),
        fees(fees),
        refundi(refundi)
    {        
        value_s_packed.allocate(pb, "value_s_packed");
        subcost_packed.allocate(pb, "subcost_packed");
        subdist_packed.allocate(pb, "subdist_packed");
        dist_packed.allocate(pb, "dist_packed");
        fees_packed.allocate(pb, "fees_packed");
        refundi_packed.allocate(pb, "refundi_packed");
        tmp_packed.allocate(pb, "tmp_packed");
        tmp.allocate(pb, 64);
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
                subcost[i],
                "boolean_subcost"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                subdist[i],
                "boolean_subdist"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                dist[i],
                "boolean_dist"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                fees[i],
                "boolean_fees"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                refundi[i],
                "boolean_refundi"
            );
        }
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>( // 64位的bool约束
                this->pb,
                tmp[i],
                "boolean_tmp"
            );
        }

        /*
        1、需要证明的等式约束
        cost_i=cost×dist_i/(Σdist_i)
        转化为两个乘法等式
        ==> cost_i * Σdist_i = cost * dist_i
        ==> cost_i * Σdist_i = tmp AND cost * dist_i = tmp

        2、refund_i = fees - cost_i

        */
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(this->subdist_packed, this->value_s_packed, this->tmp_packed),
                                 FMT(this->annotation_prefix, " equal"));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(this->subcost_packed, this->dist_packed, this->tmp_packed),
                                 FMT(this->annotation_prefix, " equal"));
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, (this->fees_packed - this->value_s_packed), this->refundi_packed),
                                 FMT(this->annotation_prefix, " equal"));

        sn_s->generate_r1cs_constraints(); // 随机数的约束
        r_s->generate_r1cs_constraints(); // 随机数的约束
        r->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const Note& notes, const NoteC& notecmtt, uint64_t dist_data, uint64_t subdist_data,uint64_t fees_data,uint64_t cost_data) { // 为变量生成约束        

        value_s.fill_with_bits(this->pb, uint64_to_bool_vector(cost_data));//cost_i
        this->pb.lc_val(value_s_packed) = value_s.get_field_element_from_bits_by_order(this->pb);

        refundi.fill_with_bits(this->pb, uint64_to_bool_vector(notes.value));//refund_i
        this->pb.lc_val(refundi_packed) = refundi.get_field_element_from_bits_by_order(this->pb);

        fees.fill_with_bits(this->pb, uint64_to_bool_vector(fees_data));//fees
        this->pb.lc_val(fees_packed) = fees.get_field_element_from_bits_by_order(this->pb);

        sn_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.sn));
        r_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.r));

        subcost.fill_with_bits(this->pb, uint64_to_bool_vector(notecmtt.value));//Σcost
        this->pb.lc_val(subcost_packed) = subcost.get_field_element_from_bits_by_order(this->pb);
        
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notecmtt.r));

        dist.fill_with_bits(this->pb, uint64_to_bool_vector(dist_data));//dist_i
        this->pb.lc_val(dist_packed) = dist.get_field_element_from_bits_by_order(this->pb);

        subdist.fill_with_bits(this->pb, uint64_to_bool_vector(subdist_data));//Σdist_i
        this->pb.lc_val(subdist_packed) = subdist.get_field_element_from_bits_by_order(this->pb);

        tmp.fill_with_bits(this->pb, uint64_to_bool_vector(subdist_data * cost_data));//Σdist_i * cost_i
        this->pb.lc_val(tmp_packed) = tmp.get_field_element_from_bits_by_order(this->pb);
    }
};