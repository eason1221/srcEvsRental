#include "deps/sha256.h"
#include "uint256.h"
#include "util.h"


//three parameters
class NoteS {
public:
    uint64_t value;
    uint256 sn_s;
    uint256 r;

    NoteS(uint64_t value, uint256 sn, uint256 r)
        : value(value), sn_s(sn), r(r) {}


    uint256 cm() const{

        CSHA256 hasher;

        auto value_vec = convertIntToVectorLE(value);

        hasher.Write(&value_vec[0], value_vec.size());
        hasher.Write(sn_s.begin(), 32);
        hasher.Write(r.begin(), 32);

        uint256 result;
        hasher.Finalize(result.begin());

        return result;
    }
};


//two parameters
class NoteC {
public:
    uint64_t value;
    uint256 r;

    NoteC(uint64_t value, uint256 r)
        : value(value), r(r) {}


    uint256 cm() const{

        CSHA256 hasher;

        auto value_vec = convertIntToVectorLE(value);

        hasher.Write(&value_vec[0], value_vec.size());
        hasher.Write(r.begin(), 32);

        uint256 result;
        hasher.Finalize(result.begin());

        return result;
    }
};