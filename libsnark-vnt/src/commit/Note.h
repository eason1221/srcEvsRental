#include "deps/sha256.h"
#include "uint256.h"
#include "util.h"
//#include "deps/sodium.h"

// uint256 random_uint256()
// {
//     uint256 ret;
//     randombytes_buf(ret.begin(), 32);

//     return ret;
// }

class NoteS {
public:
    uint64_t value;
    uint256 sn_s;
    uint256 r;
    uint256 sn_old;

    NoteS(uint64_t value, uint256 sn, uint256 r, uint256 sn_old)
        : value(value), sn_s(sn), r(r), sn_old(sn_old) {}


    uint256 cm() const{

        CSHA256 hasher;

        auto value_vec = convertIntToVectorLE(value);

        hasher.Write(&value_vec[0], value_vec.size());
        hasher.Write(sn_s.begin(), 32);
        hasher.Write(r.begin(), 32);
        hasher.Write(sn_old.begin(), 32);

        uint256 result;
        hasher.Finalize(result.begin());

        return result;
    }
};
