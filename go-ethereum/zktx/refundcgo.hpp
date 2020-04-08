#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    char *genCMT(uint64_t value, char *sn_string, char *r_string);
    char* genRoot(char* cmtarray,int n);
    char *genDepositproof(uint64_t value,
                          uint64_t value_old,
                          char *sn_old_string,
                          char *r_old_string,
                          char *sn_string,
                          char *r_string,
                          char *sns_string,
                          char *rs_string,
                          char *cmtB_old_string,
                          char *cmtB_string,
                          uint64_t value_s,
                          char *cmtS_string,
                          char *cmtarray,
                          int n,
                          char *RT,
                          uint64_t fees,
                          uint64_t cost);

    bool verifyDepositproof(char *data, char *RT,  char *cmtb_old, char *snold, char *cmtb, char *sns_string, uint64_t fees);

#ifdef __cplusplus
} // extern "C"
#endif