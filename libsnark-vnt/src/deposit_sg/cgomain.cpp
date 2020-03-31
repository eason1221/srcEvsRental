#include "deposit_sgcgo.hpp"
#include <string.h>
#include <iostream>
#include <time.h>

using namespace std;


bool test_deposit_sg_cgo_with_instance(
                            uint64_t value,
                            uint64_t value_old,
                            uint64_t value_s
                        )
{
   
    char *sn_old = (char*)"123456";//random_uint256();
    char *r_old = (char*)"123456";//random_uint256();
    char *sn = (char*)"123";
    char *r = (char*)"123";
    char *sn_s = (char*)"1234";
    char *r_s = (char*)"1234";
    char *cmtB_old = genCMT(value_old,sn_old,r_old);
    char *cmtB = genCMT(value,sn,r);
    char *cmtS = genCMT(value_s,sn_s,r_s);
    char *cmtarray = new char[32*66+1];
    int n = 32;
    char *RT;

    for(int i=0;i<n;i++){
        if(i==9)
        {
            strcat(cmtarray,"0x");
            strcat(cmtarray,cmtS);
        }else
        {
            char *cmt= (char*)"0x0000000000000000000000000000000000000000000000000000000000001001";
            strcat(cmtarray,cmt);
        }
    }

    RT=genRoot(cmtarray,n);
   
    char *proof = genDepositsgproof(value,
                                    value_old,
                                    sn_old,
                                    r_old,
                                    sn,
                                    r,
                                    sn_s,
                                    r_s,
                                    cmtB_old,
                                    cmtB,
                                    value_s,
                                    cmtS,
                                    cmtarray,
                                    32,
                                    RT
                                    );

    // verify proof
    if (proof != NULL) {
        if(strlen(proof)==0)
        {
            printf("generate deposit_sg proof fail!!!\n");
            return false;
        }else {
            printf("%s\n",proof);
            printf("RT:%s\n",RT);
            printf("sn_s:%s\n",sn_s);
            printf("cmtB_old:%s\n",cmtB_old);
            printf("sn_old:%s\n",sn_old);
            printf("cmtB:%s\n",cmtB);

            bool result = verifyDepositsgproof(proof, 
                                        RT, 
                                        sn_s,
                                        cmtB_old,
                                        sn_old,
                                        cmtB
                                      );
         
            if (!result){
                 cout << "Verifying deposit_sg proof unsuccessfully!!!" << endl;
            } else {
                cout << "Verifying deposit_sg proof successfully!!!" << endl;
            }
        
            return result;
        }
        
    }else{
        return false;
    } 
}



int main()
{
    // uint64_t value = uint64_t(264); 
    // uint64_t value_old = uint64_t(255); 
    // uint64_t value_s = uint64_t(9);

    //test_deposit_sg_cgo_with_instance(value, value_old, value_s);

    char* proof=(char*)"1e9cacf0d4164034d9eb8e5a3127388c1ea58d064cb94a042d062416a19a9e6403186595970943cdd24f9f03b0757389ff16d86f7a4ae3afeca360ac5d9b8cdc12979e6bab4e853b7f99aeaeb51a1a70049a826a72697a47611914dbe90e3fd229d0f94d1e18ac4713cd371e24b90c9beb4fdd1c70591c53b1ecdf074e85308c26fd8e88ec32a78c74714f24eb746b0faab9decb9de8c139e9bd201d76f0eba019b183417ead1ec718194759cf91e8cb474bf3782f12cc3f249a73fb80220e6421019431ab6b8d354f24a0bc0a08523e1891ac276ab1ce62079337024ac149eb0dacfea073eec900fb4457ef01ba9b2292336f5c7d16b9c43d9f68ca2d8751081dd819e3b4649cd02802cdf355826c61fd49912f142d86a8911de7d6ecadb2500a5adc4e223bc64f694f06124a27900552984937bf02d90fafcaf2c06121b7630edcbbbdb4d6c8ab99d83fe84997d4019e1502565311f62ffd86f25455668c4d189a3b0c0891f53fc99f0f890bac47a35954985d0f7ff22e530ee0115825f5262aeb85edbd48557b099418bba32970c85ce8df0f36ba0c94c609b320ed4a21f01c5e88e2a667be5c5d10ae6e1930a67eb893433babcbd2af75d00a4be07223cd0107255c35de7e3d8febf470e607acd4857b144c4b6074f8b44a18b94cfea3a21c5d1d59d000bc6ca4f724a082b860b9356645c89c8e58e98228c18d8415c6e52b4f4afe6bc61d1899a614e86076d5802869124966974b906c91bc5a3bfd36600db571dff6f0a3003bc49fc034ba2c593f387fb26d7215f8393983e94daa479c";
    char* RT=(char*)"357c076822951fbafe2636176401574831b99d114225eea73daacc3b6fa2bd81";
    char* sn_s=(char*)"1234";
    char* cmtB_old=(char*)"faf9947be5b17fa6660cb36bcd6dea1735e429eeca914ef9ba501aeccbbcc8cf";
    char* sn_old=(char*)"123456";
    char* cmtB=(char*)"9a7ab6509dc6272614d4cdb484f46ef4b0a3b4c35bab6e6809e5a65238ca37c2";

    clock_t begin=clock();
    for (size_t i = 0; i < 1000; i++)
    {
        verifyDepositsgproof(proof, RT, sn_s, cmtB_old, sn_old, cmtB);
    }
    clock_t end=clock();
    printf("%f ms\n",(end-begin)*1.0/1000000);

    return 0;
}