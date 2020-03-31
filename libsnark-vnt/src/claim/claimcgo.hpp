#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    char *genCMT(uint64_t value, char *sn_string, char *r_string);
    char *genCMT2(uint64_t value, char *r_string);

    char *genClaimproof(
                        char *sn_s_string,
                        char *r_s_string,
                        char *cmt_s_string,
                        char *r_string,
                        char *cmt_t_string,
                        uint64_t cost,
                        uint64_t subcost,
                        uint64_t dist,
                        uint64_t subdist
                    );

    bool verifyClaimproof(
                        char *data, 
                        char *cmtS_string, 
                        char *cmtt_string,  
                        uint64_t subdist,
                        uint64_t dist
                    );

#ifdef __cplusplus
} // extern "C"
#endif