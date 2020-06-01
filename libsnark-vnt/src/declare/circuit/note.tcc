/*****************************************************
 * note_gadget_with_packing for packing value_s
 * ***************************************************/
template<typename FieldT>
class note_gadget_with_packing : public gadget<FieldT> { // 基类和比较类组合，基本的note_gadget
public:    
    std::shared_ptr<digest_variable<FieldT>> sn_s; // 256位的随机数serial number
    std::shared_ptr<digest_variable<FieldT>> r_s; // 256位的随机数r
    std::shared_ptr<digest_variable<FieldT>> r; // 256位的随机数r

    pb_variable_array<FieldT> subcost; // 总支付租车费用 = cost
    pb_variable<FieldT> subcost_packed;

    pb_variable_array<FieldT> dist; // 租车里程 = dist
    pb_variable<FieldT> dist_packed;

    note_gadget_with_packing(
        protoboard<FieldT> &pb,
        std::shared_ptr<digest_variable<FieldT>> &sn_s,
        std::shared_ptr<digest_variable<FieldT>> &r_s,
        pb_variable_array<FieldT> &subcost,
        std::shared_ptr<digest_variable<FieldT>> &r,
        pb_variable_array<FieldT> &dist
    ) : gadget<FieldT>(pb), 
        sn_s(sn_s),
        r_s(r_s),
        subcost(subcost),
        r(r),
        dist(dist)
    {        
        subcost_packed.allocate(pb, "subcost_packed");
        dist_packed.allocate(pb, "dist_packed");
    }

    void generate_r1cs_constraints() { 
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
                dist[i],
                "boolean_dist"
            );
        }
        /*

        1、subcost = 5 × dist 此处pn=5

        */
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(5, this->dist_packed, this->subcost_packed),
                                 FMT(this->annotation_prefix, " equal"));

        sn_s->generate_r1cs_constraints(); // 随机数的约束
        r_s->generate_r1cs_constraints(); // 随机数的约束
        r->generate_r1cs_constraints(); // 随机数的约束
    }

    void generate_r1cs_witness(const Note& notes, const NoteC& notecmtt, const NoteC& noteds) { // 为变量生成约束        

        sn_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.sn));
        r_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notes.r));

        subcost.fill_with_bits(this->pb, uint64_to_bool_vector(notecmtt.value));//subcost
        this->pb.lc_val(subcost_packed) = subcost.get_field_element_from_bits_by_order(this->pb);
        
        r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(notecmtt.r));

        dist.fill_with_bits(this->pb, uint64_to_bool_vector(noteds.value));//dist
        this->pb.lc_val(dist_packed) = dist.get_field_element_from_bits_by_order(this->pb);
    }
};