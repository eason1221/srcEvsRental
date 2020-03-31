#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    char *genCMT(uint64_t value, char *sn_string, char *r_string);
    char *genCMT_1(uint64_t value, char *r_string);
    char* genRoot(char* cmtarray,int n);
    char *genCommitproof(char *sns_string,
                          char *rs_string,
                          char *rc_string,
                          uint64_t value_s,
                          char *cmtS_string,
                          char *cmtC_string,
                          char *cmtarray,
                          int n,
                          char *RT);

    bool verifyCommitproof(char *data, char *RT, char *sns_string, char *cmtC_string);

#ifdef __cplusplus
} // extern "C"
#endif