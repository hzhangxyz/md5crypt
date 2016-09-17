#define O(x) printf("%s\n",#x);
#include <stdio.h>
int main(){

   for (int cnt = 0; cnt < 1000; ++cnt){

     O(md5_init_ctx (&ctx);)

     if ((cnt & 1) != 0)
       O(md5_process_bytes (key, key_len, &ctx);)
     else
       O(md5_process_bytes (alt_result, 16, &ctx);)

     if (cnt % 3 != 0)
       O(md5_process_bytes (salt, salt_len, &ctx);)

     if (cnt % 7 != 0)
       O(md5_process_bytes (key, key_len, &ctx);)

     if ((cnt & 1) != 0)
       O(md5_process_bytes (alt_result, 16, &ctx);)
     else
       O(md5_process_bytes (key, key_len, &ctx);)

     O(md5_finish_ctx (&ctx, alt_result);)
   }


}

