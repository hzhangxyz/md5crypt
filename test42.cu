#include <stdio.h>

static __constant__ const char md5_salt_prefix[] = "$1$";
static __constant__ const char b64t[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static __constant__ const unsigned char fillbuf[64] = { 0x80, 0 };

struct md5_ctx{
  unsigned int A;
  unsigned int B;
  unsigned int C;
  unsigned int D;

  unsigned int total[2];
  unsigned int buflen;
  union{
    char buffer[128];
    unsigned int buffer32[32];
  };
};

#define FF(b, c, d) (d ^ (b & (c ^ d)))
#define FG(b, c, d) FF (d, b, c)
#define FH(b, c, d) (b ^ c ^ d)
#define FI(b, c, d) (c ^ (b | ~d))

__device__ void md5_process_block (const void *buffer, size_t len, struct md5_ctx *ctx){
  unsigned int correct_words[16];
  const unsigned int *words = (const unsigned int *)buffer;
  size_t nwords = len / sizeof (unsigned int);

  unsigned int A = ctx->A;
  unsigned int B = ctx->B;
  unsigned int C = ctx->C;
  unsigned int D = ctx->D;
  unsigned int lolen = len;

  ctx->total[0] += lolen;
  ctx->total[1] += (len >> 32) + (ctx->total[0] < lolen);

  for(int cnt = 0; cnt < nwords/16; cnt++){
    unsigned int *cwp = correct_words;
    unsigned int A_save = A;
    unsigned int B_save = B;
    unsigned int C_save = C;
    unsigned int D_save = D;

#define OP(a, b, c, d, s, T)                            \
    a += FF (b, c, d) + (*cwp++ = (*words)) + T;        \
    ++words;                                            \
    CYCLIC (a, s);                                      \
    a += b;

#define CYCLIC(w, s) (w = (w << s) | (w >> (32 - s)))

    /* Round 1.  */
    OP (A, B, C, D,  7, 0xd76aa478);
    OP (D, A, B, C, 12, 0xe8c7b756);
    OP (C, D, A, B, 17, 0x242070db);
    OP (B, C, D, A, 22, 0xc1bdceee);
    OP (A, B, C, D,  7, 0xf57c0faf);
    OP (D, A, B, C, 12, 0x4787c62a);
    OP (C, D, A, B, 17, 0xa8304613);
    OP (B, C, D, A, 22, 0xfd469501);
    OP (A, B, C, D,  7, 0x698098d8);
    OP (D, A, B, C, 12, 0x8b44f7af);
    OP (C, D, A, B, 17, 0xffff5bb1);
    OP (B, C, D, A, 22, 0x895cd7be);
    OP (A, B, C, D,  7, 0x6b901122);
    OP (D, A, B, C, 12, 0xfd987193);
    OP (C, D, A, B, 17, 0xa679438e);
    OP (B, C, D, A, 22, 0x49b40821);

#undef OP
#define OP(f, a, b, c, d, k, s, T)                \
    a += f (b, c, d) + correct_words[k] + T;      \
    CYCLIC (a, s);                                \
    a += b;

    /* Round 2.  */
    OP (FG, A, B, C, D,  1,  5, 0xf61e2562);
    OP (FG, D, A, B, C,  6,  9, 0xc040b340);
    OP (FG, C, D, A, B, 11, 14, 0x265e5a51);
    OP (FG, B, C, D, A,  0, 20, 0xe9b6c7aa);
    OP (FG, A, B, C, D,  5,  5, 0xd62f105d);
    OP (FG, D, A, B, C, 10,  9, 0x02441453);
    OP (FG, C, D, A, B, 15, 14, 0xd8a1e681);
    OP (FG, B, C, D, A,  4, 20, 0xe7d3fbc8);
    OP (FG, A, B, C, D,  9,  5, 0x21e1cde6);
    OP (FG, D, A, B, C, 14,  9, 0xc33707d6);
    OP (FG, C, D, A, B,  3, 14, 0xf4d50d87);
    OP (FG, B, C, D, A,  8, 20, 0x455a14ed);
    OP (FG, A, B, C, D, 13,  5, 0xa9e3e905);
    OP (FG, D, A, B, C,  2,  9, 0xfcefa3f8);
    OP (FG, C, D, A, B,  7, 14, 0x676f02d9);
    OP (FG, B, C, D, A, 12, 20, 0x8d2a4c8a);

    /* Round 3.  */
    OP (FH, A, B, C, D,  5,  4, 0xfffa3942);
    OP (FH, D, A, B, C,  8, 11, 0x8771f681);
    OP (FH, C, D, A, B, 11, 16, 0x6d9d6122);
    OP (FH, B, C, D, A, 14, 23, 0xfde5380c);
    OP (FH, A, B, C, D,  1,  4, 0xa4beea44);
    OP (FH, D, A, B, C,  4, 11, 0x4bdecfa9);
    OP (FH, C, D, A, B,  7, 16, 0xf6bb4b60);
    OP (FH, B, C, D, A, 10, 23, 0xbebfbc70);
    OP (FH, A, B, C, D, 13,  4, 0x289b7ec6);
    OP (FH, D, A, B, C,  0, 11, 0xeaa127fa);
    OP (FH, C, D, A, B,  3, 16, 0xd4ef3085);
    OP (FH, B, C, D, A,  6, 23, 0x04881d05);
    OP (FH, A, B, C, D,  9,  4, 0xd9d4d039);
    OP (FH, D, A, B, C, 12, 11, 0xe6db99e5);
    OP (FH, C, D, A, B, 15, 16, 0x1fa27cf8);
    OP (FH, B, C, D, A,  2, 23, 0xc4ac5665);

    /* Round 4.  */
    OP (FI, A, B, C, D,  0,  6, 0xf4292244);
    OP (FI, D, A, B, C,  7, 10, 0x432aff97);
    OP (FI, C, D, A, B, 14, 15, 0xab9423a7);
    OP (FI, B, C, D, A,  5, 21, 0xfc93a039);
    OP (FI, A, B, C, D, 12,  6, 0x655b59c3);
    OP (FI, D, A, B, C,  3, 10, 0x8f0ccc92);
    OP (FI, C, D, A, B, 10, 15, 0xffeff47d);
    OP (FI, B, C, D, A,  1, 21, 0x85845dd1);
    OP (FI, A, B, C, D,  8,  6, 0x6fa87e4f);
    OP (FI, D, A, B, C, 15, 10, 0xfe2ce6e0);
    OP (FI, C, D, A, B,  6, 15, 0xa3014314);
    OP (FI, B, C, D, A, 13, 21, 0x4e0811a1);
    OP (FI, A, B, C, D,  4,  6, 0xf7537e82);
    OP (FI, D, A, B, C, 11, 10, 0xbd3af235);
    OP (FI, C, D, A, B,  2, 15, 0x2ad7d2bb);
    OP (FI, B, C, D, A,  9, 21, 0xeb86d391);

    A += A_save;
    B += B_save;
    C += C_save;
    D += D_save;
  }

  ctx->A = A;
  ctx->B = B;
  ctx->C = C;
  ctx->D = D;
}

__device__ void md5_init_ctx (struct md5_ctx *ctx){
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;
  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}

__device__ void md5_process_bytes (const void *buffer, size_t len, struct md5_ctx *ctx){

  memcpy (&ctx->buffer[ctx->buflen], buffer, len);

  ctx->buflen += len;

}

__device__ void md5_finish_ctx (struct md5_ctx *ctx, void *resbuf){
  unsigned int bytes = ctx->buflen;
  size_t pad;

  ctx->total[0] += bytes;
  ctx->total[1] += (ctx->total[0] < bytes);

  pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
  memcpy (&ctx->buffer[bytes], fillbuf, pad);

  ctx->buffer32[(bytes + pad) / 4] = (ctx->total[0] << 3);
  ctx->buffer32[(bytes + pad + 4) / 4] = (ctx->total[1] << 3) | (ctx->total[0] >> 29);

  md5_process_block (ctx->buffer, bytes + pad + 8, ctx);

  ((unsigned int *) resbuf)[0] = ctx->A;
  ((unsigned int *) resbuf)[1] = ctx->B;
  ((unsigned int *) resbuf)[2] = ctx->C;
  ((unsigned int *) resbuf)[3] = ctx->D;
}

__device__ void md5crypt(char* salt, char* key, char* buffer, size_t salt_len, size_t key_len){

  unsigned char alt_result[16];
  char *cp;

  struct md5_ctx ctx;

  md5_init_ctx (&ctx);
  md5_process_bytes (key, key_len, &ctx);
  md5_process_bytes (salt, salt_len, &ctx);
  md5_process_bytes (key, key_len, &ctx);
  md5_finish_ctx (&ctx, alt_result);

  md5_init_ctx (&ctx);
  md5_process_bytes (key, key_len, &ctx);
  md5_process_bytes (md5_salt_prefix, sizeof (md5_salt_prefix) - 1, &ctx);
  md5_process_bytes (salt, salt_len, &ctx);

  for (int cnt = 0; cnt < key_len/16; cnt++)
    md5_process_bytes (alt_result, 16, &ctx);
  md5_process_bytes (alt_result, key_len%16, &ctx);

  *alt_result = 0;

  for (int cnt = key_len; cnt > 0; cnt >>= 1)
    md5_process_bytes ((cnt & 1) != 0 ? (const void *) alt_result : (const void *) key, 1, &ctx);

  md5_finish_ctx (&ctx, alt_result);
  #pragma unroll
  for (int cnt = 0; cnt < 1000; ++cnt){

    md5_init_ctx (&ctx);

    if ((cnt & 1) != 0)
      md5_process_bytes (key, key_len, &ctx);
    else
      md5_process_bytes (alt_result, 16, &ctx);

    if (cnt % 3 != 0)
      md5_process_bytes (salt, salt_len, &ctx);

    if (cnt % 7 != 0)
      md5_process_bytes (key, key_len, &ctx);

    if ((cnt & 1) != 0)
      md5_process_bytes (alt_result, 16, &ctx);
    else
      md5_process_bytes (key, key_len, &ctx);

    md5_finish_ctx (&ctx, alt_result);
  }

  cp = buffer;

#define b64_from_24bit(b2,b1,b0,N)                  \
  {                                                 \
    unsigned int w = (b2 << 16) | (b1 << 8) | b0;   \
    for(int cnt=0;cnt<(N);cnt++){                   \
      *cp++ = b64t[w & 0x3f];                       \
      w >>= 6;                                      \
    }                                               \
  }

  b64_from_24bit (alt_result[0], alt_result[6], alt_result[12], 4);
  b64_from_24bit (alt_result[1], alt_result[7], alt_result[13], 4);
  b64_from_24bit (alt_result[2], alt_result[8], alt_result[14], 4);
  b64_from_24bit (alt_result[3], alt_result[9], alt_result[15], 4);
  b64_from_24bit (alt_result[4], alt_result[10], alt_result[5], 4);
  b64_from_24bit (0, 0, alt_result[11], 2);

  *cp = 0;
}

__global__ void md5crypt_gate(int *salt_len_a,int *key_len_a,char **salt_a,char **key_a, char *hash,int* flag){
  int t = blockDim.x * blockIdx.x + threadIdx.x;
  char buffer[32];
  char l_key[32];
  char l_salt[32];
  memcpy(l_salt,salt_a[t],salt_len_a[t]+1);
  memcpy(l_key,key_a[t],key_len_a[t]+1);

//  for(int i = 0 ; i < 1024; i ++)
  md5crypt(l_salt,l_key,buffer,salt_len_a[t],key_len_a[t]);

  int f = 1;
  for(int i = 0;i<22;i++)
    if(buffer[i]!=hash[i])
        f = 0;
  if(f)
    *flag = t;
}

#define CUDA_malloc_and_memcpy(dst,src,len)                  \
    cudaMalloc((void**)&(dst),(len));                        \
    cudaMemcpy((dst), (src) ,(len), cudaMemcpyHostToDevice); \

#ifndef BL
#define BL 1
#endif

#ifndef TH
#define TH 256
#endif

int main(){
  char* key;
  char* salt;
  char* hash;

  CUDA_malloc_and_memcpy(hash,"OKuSn268wgnMGHee3mENR.",23 * sizeof(char));
  CUDA_malloc_and_memcpy(salt,"8UbX8cck",9 * sizeof(char));
  CUDA_malloc_and_memcpy(key,"qwertyui",9 * sizeof(char));

  char* salt_p[BL*TH];
  char* key_p[BL*TH];
  int salt_len[BL*TH];
  int key_len[BL*TH];
  for(int i = 0 ; i < BL*TH ; i ++){
      salt_p[i] = salt;
      key_p[i] = key;
      salt_len[i] = 8;
      key_len[i] = 8;
  }
  char** salt_dp;
  char** key_dp;
  int* salt_dl;
  int* key_dl;

  CUDA_malloc_and_memcpy(salt_dp,salt_p,BL*TH*sizeof(char*));
  CUDA_malloc_and_memcpy(key_dp,key_p,BL*TH*sizeof(char*));
  CUDA_malloc_and_memcpy(salt_dl,salt_len,BL*TH*sizeof(int));
  CUDA_malloc_and_memcpy(key_dl,key_len,BL*TH*sizeof(int))

  int *flag;
  int n = -1;
  CUDA_malloc_and_memcpy(flag,&n,sizeof(int));

//  for(int i = 0 ; i < 1024; i ++)
  md5crypt_gate<<<BL,TH>>>(salt_dl,key_dl,salt_dp,key_dp,hash,flag);

  cudaMemcpy(&n, flag ,sizeof(int), cudaMemcpyDeviceToHost);

  printf("%d\n",n);

  return 0;
}
