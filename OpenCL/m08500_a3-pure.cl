/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

CONSTANT_VK u32a c_ascii_to_ebcdic_pc[256] =
{
  // little hack, can't crack 0-bytes in password, but who cares
  //    0xab, 0xa8, 0xae, 0xad, 0xc4, 0xf1, 0xf7, 0xf4, 0x86, 0xa1, 0xe0, 0xbc, 0xb3, 0xb0, 0xb6, 0xb5,
  0x2a, 0xa8, 0xae, 0xad, 0xc4, 0xf1, 0xf7, 0xf4, 0x86, 0xa1, 0xe0, 0xbc, 0xb3, 0xb0, 0xb6, 0xb5,
  0x8a, 0x89, 0x8f, 0x8c, 0xd3, 0xd0, 0xce, 0xe6, 0x9b, 0x98, 0xd5, 0xe5, 0x92, 0x91, 0x97, 0x94,
  0x2a, 0x34, 0x54, 0x5d, 0x1c, 0x73, 0x0b, 0x51, 0x31, 0x10, 0x13, 0x37, 0x7c, 0x6b, 0x3d, 0x68,
  0x4a, 0x49, 0x4f, 0x4c, 0x43, 0x40, 0x46, 0x45, 0x5b, 0x58, 0x5e, 0x16, 0x32, 0x57, 0x76, 0x75,
  0x52, 0x29, 0x2f, 0x2c, 0x23, 0x20, 0x26, 0x25, 0x3b, 0x38, 0x08, 0x0e, 0x0d, 0x02, 0x01, 0x07,
  0x04, 0x1a, 0x19, 0x6e, 0x6d, 0x62, 0x61, 0x67, 0x64, 0x7a, 0x79, 0x3e, 0x6b, 0x1f, 0x15, 0x70,
  0x58, 0xa8, 0xae, 0xad, 0xa2, 0xa1, 0xa7, 0xa4, 0xba, 0xb9, 0x89, 0x8f, 0x8c, 0x83, 0x80, 0x86,
  0x85, 0x9b, 0x98, 0xef, 0xec, 0xe3, 0xe0, 0xe6, 0xe5, 0xfb, 0xf8, 0x2a, 0x7f, 0x0b, 0xe9, 0xa4,
  0xea, 0xe9, 0xef, 0xec, 0xe3, 0x80, 0xa7, 0x85, 0xfb, 0xf8, 0xfe, 0xfd, 0xf2, 0xb9, 0xbf, 0x9d,
  0xcb, 0xc8, 0x9e, 0xcd, 0xc2, 0xc1, 0xc7, 0xba, 0xda, 0xd9, 0xdf, 0xdc, 0xa2, 0x83, 0xd6, 0x68,
  0x29, 0x2f, 0x2c, 0x23, 0x20, 0x26, 0x25, 0x3b, 0x38, 0x08, 0x0e, 0x0d, 0x02, 0x01, 0x07, 0x04,
  0x1a, 0x19, 0x6e, 0x6d, 0x62, 0x61, 0x67, 0x64, 0x7a, 0x79, 0x4a, 0x49, 0x4f, 0x4c, 0x43, 0x40,
  0x46, 0x45, 0x5b, 0xab, 0xbf, 0xbc, 0xb3, 0xb0, 0xb6, 0xb5, 0x8a, 0x9e, 0x9d, 0x92, 0x91, 0x97,
  0x94, 0xea, 0xfe, 0xfd, 0xf2, 0xf1, 0xf7, 0xf4, 0xcb, 0xc8, 0xce, 0xcd, 0xc2, 0xc1, 0xc7, 0xc4,
  0xda, 0xd9, 0xdf, 0xdc, 0xd3, 0xd0, 0xd6, 0xd5, 0x3e, 0x3d, 0x32, 0x31, 0x37, 0x34, 0x1f, 0x1c,
  0x13, 0x10, 0x16, 0x15, 0x7f, 0x7c, 0x73, 0x70, 0x76, 0x75, 0x5e, 0x5d, 0x52, 0x51, 0x57, 0x54,
};

#if   VECT_SIZE == 1
#define BOX1(i,S) (S)[(i)]
#elif VECT_SIZE == 2
#define BOX1(i,S) make_u32x ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define BOX1(i,S) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define BOX1(i,S) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define BOX1(i,S) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

DECLSPEC u32x transform_racf_word (const u32x w, SHM_TYPE u32 *s_ascii_to_ebcdic_pc)
{
  const u32x b0 = BOX1 (((w >>  0) & 0xff), s_ascii_to_ebcdic_pc);
  const u32x b1 = BOX1 (((w >>  8) & 0xff), s_ascii_to_ebcdic_pc);
  const u32x b2 = BOX1 (((w >> 16) & 0xff), s_ascii_to_ebcdic_pc);
  const u32x b3 = BOX1 (((w >> 24) & 0xff), s_ascii_to_ebcdic_pc);

  return hc_byte_perm (b0, b1, 0x1140)
       | hc_byte_perm (b2, b3, 0x4011);
}

DECLSPEC u32 transform_racf_word_S (const u32 w)
{
  return c_ascii_to_ebcdic_pc[(w >>  0) & 0xff] <<  0
       | c_ascii_to_ebcdic_pc[(w >>  8) & 0xff] <<  8
       | c_ascii_to_ebcdic_pc[(w >> 16) & 0xff] << 16
       | c_ascii_to_ebcdic_pc[(w >> 24) & 0xff] << 24;
}

DECLSPEC void racf_des_pc1_S (u32 c, u32 d, PRIVATE_AS u32 *c_pc1, PRIVATE_AS u32 *d_pc1)
{
  PERM_OP_S  (d, c, 4, 0x0f0f0f0f);
  HPERM_OP_S (c,    2, 0xcccc0000);
  HPERM_OP_S (d,    2, 0xcccc0000);
  PERM_OP_S  (d, c, 1, 0x55555555);
  PERM_OP_S  (c, d, 8, 0x00ff00ff);
  PERM_OP_S  (d, c, 1, 0x55555555);

  *d_pc1 = ((d & 0x000000ff) << 16)
         | ((d & 0x0000ff00) <<  0)
         | ((d & 0x00ff0000) >> 16)
         | ((c & 0xf0000000) >>  4);

  *c_pc1 = c & 0x0fffffff;
}

DECLSPEC void racf_des_keysetup_vect (u32x c, const u32 c_pc1, const u32 d_pc1, PRIVATE_AS u32x *Kc, PRIVATE_AS u32x *Kd, SHM_TYPE u32 (*s_skb)[64])
{
  u32x d = 0;

  PERM_OP  (d, c, 4, 0x0f0f0f0f);
  HPERM_OP (c,    2, 0xcccc0000);
  HPERM_OP (d,    2, 0xcccc0000);
  PERM_OP  (d, c, 1, 0x55555555);
  PERM_OP  (c, d, 8, 0x00ff00ff);
  PERM_OP  (d, c, 1, 0x55555555);

  d = ((d & 0x000000ff) << 16)
    | ((d & 0x0000ff00) <<  0)
    | ((d & 0x00ff0000) >> 16)
    | ((c & 0xf0000000) >>  4);

  c = c & 0x0fffffff;

  c |= c_pc1;
  d |= d_pc1;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 16; i++)
  {
    if ((i < 2) || (i == 8) || (i == 15))
    {
      c = ((c >> 1) | (c << 27));
      d = ((d >> 1) | (d << 27));
    }
    else
    {
      c = ((c >> 2) | (c << 26));
      d = ((d >> 2) | (d << 26));
    }

    c = c & 0x0fffffff;
    d = d & 0x0fffffff;

    const u32x c00 = (c >>  0) & 0x0000003f;
    const u32x c06 = (c >>  6) & 0x00383003;
    const u32x c07 = (c >>  7) & 0x0000003c;
    const u32x c13 = (c >> 13) & 0x0000060f;
    const u32x c20 = (c >> 20) & 0x00000001;

    u32x s = DES_BOX (((c00 >>  0) & 0xff), 0, s_skb)
           | DES_BOX (((c06 >>  0) & 0xff)
                     |((c07 >>  0) & 0xff), 1, s_skb)
           | DES_BOX (((c13 >>  0) & 0xff)
                     |((c06 >>  8) & 0xff), 2, s_skb)
           | DES_BOX (((c20 >>  0) & 0xff)
                     |((c13 >>  8) & 0xff)
                     |((c06 >> 16) & 0xff), 3, s_skb);

    const u32x d00 = (d >>  0) & 0x00003c3f;
    const u32x d07 = (d >>  7) & 0x00003f03;
    const u32x d21 = (d >> 21) & 0x0000000f;
    const u32x d22 = (d >> 22) & 0x00000030;

    u32x t = DES_BOX (((d00 >>  0) & 0xff), 4, s_skb)
           | DES_BOX (((d07 >>  0) & 0xff)
                     |((d00 >>  8) & 0xff), 5, s_skb)
           | DES_BOX (((d07 >>  8) & 0xff), 6, s_skb)
           | DES_BOX (((d21 >>  0) & 0xff)
                     |((d22 >>  0) & 0xff), 7, s_skb);

    Kc[i] = ((t << 16) | (s & 0x0000ffff));
    Kd[i] = ((s >> 16) | (t & 0xffff0000));

    Kc[i] = hc_rotl32 (Kc[i], 2u);
    Kd[i] = hc_rotl32 (Kd[i], 2u);
  }
}

DECLSPEC void m08500m (LOCAL_AS u32 (*s_SPtrans)[64], LOCAL_AS u32 (*s_skb)[64], PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR (), SHM_TYPE u32 *s_ascii_to_ebcdic_pc)
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32x data[2];

  data[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  data[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];

  /**
   * loop
   */

  u32 w0l = w[0];

  u32 w1 = w[1];

  const u32 d = transform_racf_word_S (w1);

  u32 c_pc1;
  u32 d_pc1;

  racf_des_pc1_S (0, d, &c_pc1, &d_pc1);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    /**
     * RACF
     */

    const u32x c = transform_racf_word (w0, s_ascii_to_ebcdic_pc);

    u32x Kc[16];
    u32x Kd[16];

    racf_des_keysetup_vect (c, c_pc1, d_pc1, Kc, Kd, s_skb);

    u32x iv[2];

    _des_crypt_encrypt_racf_vect (iv, data, Kc, Kd, s_SPtrans);

    u32x z = 0;

    COMPARE_M_SIMD (iv[0], iv[1], z, z);
  }
}

DECLSPEC void m08500s (LOCAL_AS u32 (*s_SPtrans)[64], LOCAL_AS u32 (*s_skb)[64], PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR (), SHM_TYPE u32 *s_ascii_to_ebcdic_pc)
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32x data[2];

  data[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  data[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * loop
   */

  u32 w0l = w[0];

  u32 w1 = w[1];

  const u32 d = transform_racf_word_S (w1);

  u32 c_pc1;
  u32 d_pc1;

  racf_des_pc1_S (0, d, &c_pc1, &d_pc1);

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    /**
     * RACF
     */

    const u32x c = transform_racf_word (w0, s_ascii_to_ebcdic_pc);

    u32x Kc[16];
    u32x Kd[16];

    racf_des_keysetup_vect (c, c_pc1, d_pc1, Kc, Kd, s_skb);

    u32x iv[2];

    _des_crypt_encrypt_racf_vect (iv, data, Kc, Kd, s_SPtrans);

    u32x z = 0;

    COMPARE_S_SIMD (iv[0], iv[1], z, z);
  }
}

KERNEL_FQ KERNEL_FA void m08500_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];
  LOCAL_VK u32 s_ascii_to_ebcdic_pc[256];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_ascii_to_ebcdic_pc[i] = c_ascii_to_ebcdic_pc[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;
  CONSTANT_AS u32a *s_ascii_to_ebcdic_pc = c_ascii_to_ebcdic_pc;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = 0;
  w[ 3] = 0;
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m08500m (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_ascii_to_ebcdic_pc);
}

KERNEL_FQ KERNEL_FA void m08500_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];
  LOCAL_VK u32 s_ascii_to_ebcdic_pc[256];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_ascii_to_ebcdic_pc[i] = c_ascii_to_ebcdic_pc[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;
  CONSTANT_AS u32a *s_ascii_to_ebcdic_pc = c_ascii_to_ebcdic_pc;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = 0;
  w[ 3] = 0;
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * main
   */

  m08500s (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_ascii_to_ebcdic_pc);
}
