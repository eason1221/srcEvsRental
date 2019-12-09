#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    char *genCMT(uint64_t value, char *sn_string, char *r_string);

    char *genClaimproof(char *sn_s_string,
                   char *r_s_string,
                   char *cmt_s_string,
                   uint64_t value_s);

    bool verifyClaimproof(char *data, char *cmtS_string ,uint64_t value_s);

#ifdef __cplusplus
} // extern "C"
#endif