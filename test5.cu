#include <stdio.h>
#include <stdio.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

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

__device__ __forceinline__ void md5_process_block (const void *buffer, size_t len, struct md5_ctx *ctx){
  unsigned int correct_words[16];
  const unsigned int *words = (const unsigned int *)buffer;
  size_t nwords = len / sizeof (unsigned int);
  const unsigned int *endp = words + nwords;
  unsigned int A = ctx->A;
  unsigned int B = ctx->B;
  unsigned int C = ctx->C;
  unsigned int D = ctx->D;
  unsigned int lolen = len;

  ctx->total[0] += lolen;
  ctx->total[1] += (len >> 32) + (ctx->total[0] < lolen);

  while (words < endp){
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

__device__ __forceinline__ void * md5_read_ctx (const struct md5_ctx *ctx, void *resbuf){
  ((unsigned int *) resbuf)[0] = ctx->A;
  ((unsigned int *) resbuf)[1] = ctx->B;
  ((unsigned int *) resbuf)[2] = ctx->C;
  ((unsigned int *) resbuf)[3] = ctx->D;

  return resbuf;
}

__device__ __forceinline__ void md5_init_ctx (struct md5_ctx *ctx){
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;
  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}

__device__ __forceinline__ void md5_process_bytes (const void *buffer, size_t len, struct md5_ctx *ctx){
  size_t left_over = ctx->buflen;
  size_t add = MIN(len, 128 - left_over);

  memcpy (&ctx->buffer[left_over], buffer, add);
  ctx->buflen += add;

  buffer = (const char *) buffer + add;
  len -= add;

  left_over = ctx->buflen;

  memcpy (&ctx->buffer[left_over], buffer, len);
  left_over += len;

  ctx->buflen = left_over;

}

__device__ __forceinline__ void * md5_finish_ctx (struct md5_ctx *ctx, void *resbuf){
  unsigned int bytes = ctx->buflen;
  size_t pad;

  ctx->total[0] += bytes;
  ctx->total[1] += (ctx->total[0] < bytes);

  pad = bytes >= 56 ? 64 + 56 - bytes : 56 - bytes;
  memcpy (&ctx->buffer[bytes], fillbuf, pad);

  ctx->buffer32[(bytes + pad) / 4] = (ctx->total[0] << 3);
  ctx->buffer32[(bytes + pad + 4) / 4] = (ctx->total[1] << 3) | (ctx->total[0] >> 29);

  md5_process_block (ctx->buffer, bytes + pad + 8, ctx);

  return md5_read_ctx (ctx, resbuf);
}

__device__ void get_it(char* key, char* salt, char* buffer){

  unsigned char alt_result[16];
  size_t salt_len;
  size_t key_len;
  size_t cnt;
  char *cp;

  salt += sizeof (md5_salt_prefix) - 1;

  salt_len = 8;
  cp = key;
  key_len = 0;
  while(*cp!=0){cp++;key_len++;}

  struct md5_ctx ctx;
  struct md5_ctx alt_ctx;

  md5_init_ctx (&ctx);
  md5_process_bytes (key, key_len, &ctx);
  md5_process_bytes (md5_salt_prefix, sizeof (md5_salt_prefix) - 1, &ctx);
  md5_process_bytes (salt, salt_len, &ctx);

  md5_init_ctx (&alt_ctx);
  md5_process_bytes (key, key_len, &alt_ctx);
  md5_process_bytes (salt, salt_len, &alt_ctx);
  md5_process_bytes (key, key_len, &alt_ctx);
  md5_finish_ctx (&alt_ctx, alt_result);

  for (cnt = key_len; cnt > 16; cnt -= 16)
    md5_process_bytes (alt_result, 16, &ctx);
  md5_process_bytes (alt_result, cnt, &ctx);

  *alt_result = 0;

  for (cnt = key_len; cnt > 0; cnt >>= 1)
    md5_process_bytes ((cnt & 1) != 0 ? (const void *) alt_result : (const void *) key, 1, &ctx);

  md5_finish_ctx (&ctx, alt_result);

  for (cnt = 0; cnt < 1000; ++cnt){
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

  memcpy (buffer, md5_salt_prefix,sizeof(md5_salt_prefix));
  cp = buffer + sizeof (md5_salt_prefix) - 1;

  memcpy (cp, salt, salt_len);
  cp += salt_len;

  *cp++ = '$';

#define b64_from_24bit(b2,b1,b0,N)                  \
  {                                                 \
    int n=N;                                        \
    unsigned int w = (b2 << 16) | (b1 << 8) | b0;   \
    while (n-- > 0){                                \
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

__global__ void gate_hash(char* dict, char* hash, char** buffer){
  int x = threadIdx.x;
  int y = blockIdx.x;
  char temp[64];
  __shared__ char salt[64];
  char *dp = dict;
  char *hp = hash;
  char *s1;
  char *s2;
  for(int i = 0;i<x;)
    i+=(*(++dp)==0);
  dp++;
  for(int i = 0;i<y;)
    i+=(*(++hp)==0);
  hp++;
  for(int i = 0;i<12;i++)
    *(salt+i)=*(hp+i);
  *(salt+12)=0;
  get_it(dp,salt,temp);
  int flag = 1;
  s1=dp+13;
  s2=temp;
  while(*s2!=0)
    if(*s1!=*s2){
      flag=0;
      break;
    }
  if(flag)
    *(buffer+y) = dp;
}

int main(){
  FILE* fp;
  char* hash_src;
  unsigned int hash_src_len;
  char* dict_src;
  unsigned int dict_src_len;
  char* pure_salt;

  fp=fopen("hash.test","r");
  fseek(fp,0L,SEEK_END);
  hash_src_len=ftell(fp);
  hash_src = (char *) malloc(hash_src_len);
  fseek(fp,0L,SEEK_SET);
  fread(hash_src,hash_src_len,1,fp);
  fclose(fp);
  for(int i = 0; i<hash_src_len; i++)
    if(*(hash_src+i)=='\n')*(hash_src+i)=0;

  fp=fopen("dict.test","r");
  fseek(fp,0L,SEEK_END);
  dict_src_len=ftell(fp);
  dict_src = (char *) malloc(dict_src_len);
  fseek(fp,0L,SEEK_SET);
  fread(dict_src,dict_src_len,1,fp);
  fclose(fp);
  for(int i = 0; i<dict_src_len; i++)
    if(*(dict_src+i)=='\n')*(dict_src+i)=0;

  pure_salt = (char *) malloc(hash_src_len);
  for(int i = 0; i<hash_src_len; i++)
    pure_salt[i]=hash_src[i];
  int j = 0;
  for(int i = 0; i<hash_src_len; i++){
    if(pure_salt[i]=='$')j=(j+1)%3;
    if(!j)pure_salt[i+1]=0;
  }

  char* dict;
  char* hash;
  char* salt;
  char** buffer;
  char** buffer_src;
  cudaMalloc((void**)&dict,dict_src_len);
  cudaMalloc((void**)&hash,hash_src_len);
  cudaMalloc((void**)&salt,hash_src_len);
  cudaMemcpy(dict,dict_src,dict_src_len, cudaMemcpyHostToDevice);
  cudaMemcpy(hash,hash_src,hash_src_len, cudaMemcpyHostToDevice);
  cudaMemcpy(dict,pure_salt,hash_src_len, cudaMemcpyHostToDevice);
  cudaMalloc((void**)&buffer,1 * sizeof(char*));
  buffer_src = (char **)malloc (1 * sizeof(char*));
  for(int i = 0; i<1; i++)*(buffer_src+i)=0;
  cudaMemcpy(buffer,buffer_src,1 * sizeof(char*),cudaMemcpyHostToDevice);
  gate_hash<<<1,1>>>(dict,hash,buffer,p_salt);
  cudaMemcpy(buffer_src,buffer,1 * sizeof(char*),cudaMemcpyDeviceToHost);
  for(int i = 0;i<1;i++){
    if(*(buffer_src+i)) printf("*");
    else printf("-");
  }
  printf("\n");
  return 0;
}
