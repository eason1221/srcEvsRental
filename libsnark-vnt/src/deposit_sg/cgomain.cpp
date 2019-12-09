#include "deposit_sgcgo.hpp"
#include <string.h>
#include <iostream>

using namespace std;


// bool test_deposit_sg_cgo_with_instance(
//                             uint64_t value,
//                             uint64_t value_old,
//                             uint64_t value_s
//                         )
// {
   
//     char *sn_old = (char*)"123456";//random_uint256();
//     char *r_old = (char*)"123456";//random_uint256();
//     char *sn = (char*)"123";
//     char *r = (char*)"123";
//     char *sn_s = (char*)"1234";
//     char *r_s = (char*)"1234";
//     char *cmtB_old = genCMT(value_old,sn_old,r_old);
//     char *cmtB = genCMT(value,sn,r);
//     char *cmtS = genCMT(value_s,sn_s,r_s);
//     char *cmtarray = new char[32*66+1];
//     int n = 32;
//     char *RT;

//     for(int i=0;i<n;i++){
//         if(i==9)
//         {
//             strcat(cmtarray,"0x");
//             strcat(cmtarray,cmtS);
//         }else
//         {
//             char *cmt= (char*)"0x0000000000000000000000000000000000000000000000000000000000001001";
//             strcat(cmtarray,cmt);
//         }
//     }

//     RT=genRoot(cmtarray,n);
   
//     char *proof = genDepositsgproof(value,
//                                     value_old,
//                                     sn_old,
//                                     r_old,
//                                     sn,
//                                     r,
//                                     sn_s,
//                                     r_s,
//                                     cmtB_old,
//                                     cmtB,
//                                     value_s,
//                                     cmtS,
//                                     cmtarray,
//                                     32,
//                                     RT
//                                     );

//     // verify proof
//     if (proof != NULL) {
//         if(strlen(proof)==0)
//         {
//             printf("generate deposit_sg proof fail!!!\n");
//             return false;
//         }else {
//             printf("%s\n",proof);

//             //assert(verify_deposit_proof(keypair.vk, *proof));
        
//             bool result = verifyDepositsgproof(proof, 
//                                         RT, 
//                                         sn_s,
//                                         cmtB_old,
//                                         sn_old,
//                                         cmtB
//                                       );
         
//             if (!result){
//                  cout << "Verifying deposit_sg proof unsuccessfully!!!" << endl;
//             } else {
//                 cout << "Verifying deposit_sg proof successfully!!!" << endl;
//             }
        
//             return result;
//         }
        
//     }else{
//         return false;
//     } 
// }



int main()
{
    // uint64_t value = uint64_t(264); 
    // uint64_t value_old = uint64_t(255); 
    // uint64_t value_s = uint64_t(9);

    // test_deposit_sg_cgo_with_instance(value, value_old, value_s);

    // // Note. cmake can not compile the assert()  --Agzs
    uint64_t value = 1000;
    char *sn = (char*)"123";
    char *r = (char*)"123";
    char *s = genCMT(value, sn, r);
    cout << s << endl;
    return 0;
}