#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    char *genCMT(uint64_t value, char *sn_string, char *r_string);
    char* genRoot(char* cmtarray,int n);
    char *genDepositsgproof(uint64_t value,
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
                          char *RT);

    bool verifyDepositsgproof(char *data, char *RT, char *sn_s, char *cmtb_old, char *snold, char *cmtb);

#ifdef __cplusplus
} // extern "C"
#endif