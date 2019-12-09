#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>

    char *genCMT_1(uint64_t value, char *sn_string, char *r_string, char *snA_string);
    char* genRoot(char* cmtarray,int n);
    char *genCommitproof(char *sns_string,
                          char *rs_string,
                          char *snA_string,
                          uint64_t value_s,
                          char *cmtS_string,
                          char *cmtarray,
                          int n,
                          char *RT);

    bool verifyCommitproof(char *data, char *RT, char *sn_s, uint64_t values);

#ifdef __cplusplus
} // extern "C"
#endif