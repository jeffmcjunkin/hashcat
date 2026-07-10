/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_twofish.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct keepass_tmp
{
  u32 tmp_digest[8];

} keepass_tmp_t;

typedef struct keepass
{
  u32 version;
  u32 algorithm;

  /* key-file handling */
  u32 keyfile_len;
  u32 keyfile[8];

  u32 final_random_seed[8];
  u32 transf_random_seed[8];
  u32 enc_iv[4];
  u32 contents_hash[8];

  /* specific to version 1 */
  u32 contents_len;
  u32 contents[0x200000];

  /* specific to version 2 */
  u32 expected_bytes[8];

} keepass_t;

DECLSPEC void m13400_aes256_encrypt_noswap (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3, SHM_TYPE const u32 *s_te4)
{
  u32 s0 = in[0] ^ ks[0];
  u32 s1 = in[1] ^ ks[1];
  u32 s2 = in[2] ^ ks[2];
  u32 s3 = in[3] ^ ks[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[ 4];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[ 5];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[ 6];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[ 7];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[ 8];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[ 9];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[10];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[11];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[12];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[13];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[14];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[15];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[16];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[17];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[18];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[19];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[20];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[21];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[22];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[23];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[24];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[25];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[26];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[27];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[28];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[29];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[30];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[31];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[32];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[33];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[34];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[35];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[36];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[37];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[38];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[39];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[40];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[41];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[42];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[43];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[44];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[45];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[46];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[47];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[48];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[49];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[50];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[51];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[52];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[53];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[54];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[55];

  out[0] = (s_te4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ ks[56];

  out[1] = (s_te4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ ks[57];

  out[2] = (s_te4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ ks[58];

  out[3] = (s_te4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ ks[59];
}

KERNEL_FQ KERNEL_FA void m13400_init (KERN_ATTR_TMPS_ESALT (keepass_tmp_t, keepass_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha256_final (&ctx);

  u32 digest[8];

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];
  digest[4] = ctx.h[4];
  digest[5] = ctx.h[5];
  digest[6] = ctx.h[6];
  digest[7] = ctx.h[7];

  if (esalt_bufs[DIGESTS_OFFSET_HOST].version == 2 && esalt_bufs[DIGESTS_OFFSET_HOST].keyfile_len == 0)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_init (&ctx);

    sha256_update_64 (&ctx, w0, w1, w2, w3, 32);

    sha256_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
    digest[5] = ctx.h[5];
    digest[6] = ctx.h[6];
    digest[7] = ctx.h[7];
  }

  if (esalt_bufs[DIGESTS_OFFSET_HOST].keyfile_len != 0)
  {
    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = digest[5];
    w1[2] = digest[6];
    w1[3] = digest[7];
    w2[0] = esalt_bufs[DIGESTS_OFFSET_HOST].keyfile[0];
    w2[1] = esalt_bufs[DIGESTS_OFFSET_HOST].keyfile[1];
    w2[2] = esalt_bufs[DIGESTS_OFFSET_HOST].keyfile[2];
    w2[3] = esalt_bufs[DIGESTS_OFFSET_HOST].keyfile[3];
    w3[0] = esalt_bufs[DIGESTS_OFFSET_HOST].keyfile[4];
    w3[1] = esalt_bufs[DIGESTS_OFFSET_HOST].keyfile[5];
    w3[2] = esalt_bufs[DIGESTS_OFFSET_HOST].keyfile[6];
    w3[3] = esalt_bufs[DIGESTS_OFFSET_HOST].keyfile[7];

    sha256_init (&ctx);

    sha256_update_64 (&ctx, w0, w1, w2, w3, 64);

    sha256_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
    digest[5] = ctx.h[5];
    digest[6] = ctx.h[6];
    digest[7] = ctx.h[7];
  }

  tmps[gid].tmp_digest[0] = digest[0];
  tmps[gid].tmp_digest[1] = digest[1];
  tmps[gid].tmp_digest[2] = digest[2];
  tmps[gid].tmp_digest[3] = digest[3];
  tmps[gid].tmp_digest[4] = digest[4];
  tmps[gid].tmp_digest[5] = digest[5];
  tmps[gid].tmp_digest[6] = digest[6];
  tmps[gid].tmp_digest[7] = digest[7];
}

KERNEL_FQ KERNEL_FA void m13400_loop (KERN_ATTR_TMPS_ESALT (keepass_tmp_t, keepass_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /* Construct AES key */

  u32 ukey[8];

  ukey[0] = esalt_bufs[DIGESTS_OFFSET_HOST].transf_random_seed[0];
  ukey[1] = esalt_bufs[DIGESTS_OFFSET_HOST].transf_random_seed[1];
  ukey[2] = esalt_bufs[DIGESTS_OFFSET_HOST].transf_random_seed[2];
  ukey[3] = esalt_bufs[DIGESTS_OFFSET_HOST].transf_random_seed[3];
  ukey[4] = esalt_bufs[DIGESTS_OFFSET_HOST].transf_random_seed[4];
  ukey[5] = esalt_bufs[DIGESTS_OFFSET_HOST].transf_random_seed[5];
  ukey[6] = esalt_bufs[DIGESTS_OFFSET_HOST].transf_random_seed[6];
  ukey[7] = esalt_bufs[DIGESTS_OFFSET_HOST].transf_random_seed[7];

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  u32 data0[4];
  u32 data1[4];

  data0[0] = hc_swap32_S (tmps[gid].tmp_digest[0]);
  data0[1] = hc_swap32_S (tmps[gid].tmp_digest[1]);
  data0[2] = hc_swap32_S (tmps[gid].tmp_digest[2]);
  data0[3] = hc_swap32_S (tmps[gid].tmp_digest[3]);
  data1[0] = hc_swap32_S (tmps[gid].tmp_digest[4]);
  data1[1] = hc_swap32_S (tmps[gid].tmp_digest[5]);
  data1[2] = hc_swap32_S (tmps[gid].tmp_digest[6]);
  data1[3] = hc_swap32_S (tmps[gid].tmp_digest[7]);

  for (u32 i = 0; i < LOOP_CNT; i++)
  {
    m13400_aes256_encrypt_noswap (ks, data0, data0, s_te0, s_te1, s_te2, s_te3, s_te4);
    m13400_aes256_encrypt_noswap (ks, data1, data1, s_te0, s_te1, s_te2, s_te3, s_te4);
  }

  tmps[gid].tmp_digest[0] = hc_swap32_S (data0[0]);
  tmps[gid].tmp_digest[1] = hc_swap32_S (data0[1]);
  tmps[gid].tmp_digest[2] = hc_swap32_S (data0[2]);
  tmps[gid].tmp_digest[3] = hc_swap32_S (data0[3]);
  tmps[gid].tmp_digest[4] = hc_swap32_S (data1[0]);
  tmps[gid].tmp_digest[5] = hc_swap32_S (data1[1]);
  tmps[gid].tmp_digest[6] = hc_swap32_S (data1[2]);
  tmps[gid].tmp_digest[7] = hc_swap32_S (data1[3]);
}

KERNEL_FQ KERNEL_FA void m13400_comp (KERN_ATTR_TMPS_ESALT (keepass_tmp_t, keepass_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /* hash output... */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = tmps[gid].tmp_digest[0];
  w0[1] = tmps[gid].tmp_digest[1];
  w0[2] = tmps[gid].tmp_digest[2];
  w0[3] = tmps[gid].tmp_digest[3];
  w1[0] = tmps[gid].tmp_digest[4];
  w1[1] = tmps[gid].tmp_digest[5];
  w1[2] = tmps[gid].tmp_digest[6];
  w1[3] = tmps[gid].tmp_digest[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_ctx_t ctx;

  sha256_init (&ctx);

  sha256_update_64 (&ctx, w0, w1, w2, w3, 32);

  sha256_final (&ctx);

  u32 digest[8];

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];
  digest[4] = ctx.h[4];
  digest[5] = ctx.h[5];
  digest[6] = ctx.h[6];
  digest[7] = ctx.h[7];

  /* ...then hash final_random_seed | output */

  if (esalt_bufs[DIGESTS_OFFSET_HOST].version == 1)
  {
    w0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[0];
    w0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[1];
    w0[2] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[2];
    w0[3] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[3];
    w1[0] = digest[0];
    w1[1] = digest[1];
    w1[2] = digest[2];
    w1[3] = digest[3];
    w2[0] = digest[4];
    w2[1] = digest[5];
    w2[2] = digest[6];
    w2[3] = digest[7];
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_init (&ctx);

    sha256_update_64 (&ctx, w0, w1, w2, w3, 48);

    sha256_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
    digest[5] = ctx.h[5];
    digest[6] = ctx.h[6];
    digest[7] = ctx.h[7];
  }
  else
  {
    w0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[0];
    w0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[1];
    w0[2] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[2];
    w0[3] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[3];
    w1[0] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[4];
    w1[1] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[5];
    w1[2] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[6];
    w1[3] = esalt_bufs[DIGESTS_OFFSET_HOST].final_random_seed[7];
    w2[0] = digest[0];
    w2[1] = digest[1];
    w2[2] = digest[2];
    w2[3] = digest[3];
    w3[0] = digest[4];
    w3[1] = digest[5];
    w3[2] = digest[6];
    w3[3] = digest[7];

    sha256_init (&ctx);

    sha256_update_64 (&ctx, w0, w1, w2, w3, 64);

    sha256_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
    digest[4] = ctx.h[4];
    digest[5] = ctx.h[5];
    digest[6] = ctx.h[6];
    digest[7] = ctx.h[7];
  }

  // at this point we have to distinguish between the different keypass versions

  u32 iv[4];

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_iv[0];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_iv[1];
  iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_iv[2];
  iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_iv[3];

  u32 r0 = 0;
  u32 r1 = 0;
  u32 r2 = 0;
  u32 r3 = 0;

  if (esalt_bufs[DIGESTS_OFFSET_HOST].version == 1)
  {
    sha256_ctx_t ctx;

    sha256_init (&ctx);

    if (esalt_bufs[DIGESTS_OFFSET_HOST].algorithm == 1)
    {
      /* Construct final Twofish key */
      u32 sk[4];
      u32 lk[40];

      digest[0] = hc_swap32_S (digest[0]);
      digest[1] = hc_swap32_S (digest[1]);
      digest[2] = hc_swap32_S (digest[2]);
      digest[3] = hc_swap32_S (digest[3]);
      digest[4] = hc_swap32_S (digest[4]);
      digest[5] = hc_swap32_S (digest[5]);
      digest[6] = hc_swap32_S (digest[6]);
      digest[7] = hc_swap32_S (digest[7]);

      twofish256_set_key (sk, lk, digest);

      iv[0] = hc_swap32_S (iv[0]);
      iv[1] = hc_swap32_S (iv[1]);
      iv[2] = hc_swap32_S (iv[2]);
      iv[3] = hc_swap32_S (iv[3]);

      u32 contents_len = esalt_bufs[DIGESTS_OFFSET_HOST].contents_len;

      u32 contents_pos;
      u32 contents_off;

      // process (decrypt and hash) the buffer with the biggest steps possible.

      for (contents_pos = 0, contents_off = 0; contents_pos < contents_len - 16; contents_pos += 16, contents_off += 4)
      {
        u32 data[4];

        data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 0];
        data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 1];
        data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 2];
        data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 3];

        data[0] = hc_swap32_S (data[0]);
        data[1] = hc_swap32_S (data[1]);
        data[2] = hc_swap32_S (data[2]);
        data[3] = hc_swap32_S (data[3]);

        u32 out[4];

        twofish256_decrypt (sk, lk, data, out);

        out[0] ^= iv[0];
        out[1] ^= iv[1];
        out[2] ^= iv[2];
        out[3] ^= iv[3];

        out[0] = hc_swap32_S (out[0]);
        out[1] = hc_swap32_S (out[1]);
        out[2] = hc_swap32_S (out[2]);
        out[3] = hc_swap32_S (out[3]);

        u32 w0[4] = { 0 };
        u32 w1[4] = { 0 };
        u32 w2[4] = { 0 };
        u32 w3[4] = { 0 };

        w0[0] = out[0];
        w0[1] = out[1];
        w0[2] = out[2];
        w0[3] = out[3];

        sha256_update_64 (&ctx, w0, w1, w2, w3, 16);

        iv[0] = data[0];
        iv[1] = data[1];
        iv[2] = data[2];
        iv[3] = data[3];
      }

      // we've reached the final block for decrypt, it will contain the padding bytes we're looking for

      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 3];

      data[0] = hc_swap32_S (data[0]);
      data[1] = hc_swap32_S (data[1]);
      data[2] = hc_swap32_S (data[2]);
      data[3] = hc_swap32_S (data[3]);

      u32 out[4];

      twofish256_decrypt (sk, lk, data, out);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      out[0] = hc_swap32_S (out[0]);
      out[1] = hc_swap32_S (out[1]);
      out[2] = hc_swap32_S (out[2]);
      out[3] = hc_swap32_S (out[3]);

      // now we can access the pad byte

      const u32 pad_byte = out[3] & 0xff;

      // we need to clear the buffer of the padding data

      truncate_block_4x4_be_S (out, 16 - pad_byte);

      u32 w0[4] = { 0 };
      u32 w1[4] = { 0 };
      u32 w2[4] = { 0 };
      u32 w3[4] = { 0 };

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];

      sha256_update_64 (&ctx, w0, w1, w2, w3, 16 - pad_byte);
    }
    else
    {
      /* Construct final AES key */

      #define KEYLEN 60

      u32 ks[KEYLEN];

      AES256_set_decrypt_key (ks, digest, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

      u32 contents_len = esalt_bufs[DIGESTS_OFFSET_HOST].contents_len;

      u32 contents_pos;
      u32 contents_off;

      for (contents_pos = 0, contents_off = 0; contents_pos < contents_len - 16; contents_pos += 16, contents_off += 4)
      {
        u32 data[4];

        data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 0];
        data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 1];
        data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 2];
        data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 3];

        u32 out[4];

        AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

        out[0] ^= iv[0];
        out[1] ^= iv[1];
        out[2] ^= iv[2];
        out[3] ^= iv[3];

        u32 w0[4] = { 0 };
        u32 w1[4] = { 0 };
        u32 w2[4] = { 0 };
        u32 w3[4] = { 0 };

        w0[0] = out[0];
        w0[1] = out[1];
        w0[2] = out[2];
        w0[3] = out[3];

        sha256_update_64 (&ctx, w0, w1, w2, w3, 16);

        iv[0] = data[0];
        iv[1] = data[1];
        iv[2] = data[2];
        iv[3] = data[3];
      }

      // we've reached the final block for decrypt, it will contain the padding bytes we're looking for

      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].contents[contents_off + 3];

      u32 out[4];

      AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      // now we can access the pad byte

      const u32 pad_byte = out[3] & 0xff;

      // we need to clear the buffer of the padding data

      truncate_block_4x4_be_S (out, 16 - pad_byte);

      u32 w0[4] = { 0 };
      u32 w1[4] = { 0 };
      u32 w2[4] = { 0 };
      u32 w3[4] = { 0 };

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];

      sha256_update_64 (&ctx, w0, w1, w2, w3, 16 - pad_byte);
    }

    sha256_final (&ctx);

    r0 = ctx.h[0];
    r1 = ctx.h[1];
    r2 = ctx.h[2];
    r3 = ctx.h[3];
  }
  else
  {
    /* Construct final AES key */

    #define KEYLEN 60

    u32 ks[KEYLEN];

    AES256_set_decrypt_key (ks, digest, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 data[4];

    data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].contents_hash[0];
    data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].contents_hash[1];
    data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].contents_hash[2];
    data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].contents_hash[3];

    u32 out[4];

    AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    r0 = out[0];
    r1 = out[1];
    r2 = out[2];
    r3 = out[3];
  }

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
