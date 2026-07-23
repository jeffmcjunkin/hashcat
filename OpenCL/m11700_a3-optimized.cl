/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_streebog256.cl)
#endif

#define INITVAL 0x0101010101010101UL

// Low half of LPS.  Used when only output bytes 0 and 1 of the following
// round are consumed, allowing the penultimate state to stay 32-bit.
#define SBOG_LPSti32                                          \
  l32_from_64 (BOX (s_sbob_sl64, 0, ((t[0] >> (i * 8)) & 0xff))) ^ \
  l32_from_64 (BOX (s_sbob_sl64, 1, ((t[1] >> (i * 8)) & 0xff))) ^ \
  l32_from_64 (BOX (s_sbob_sl64, 2, ((t[2] >> (i * 8)) & 0xff))) ^ \
  l32_from_64 (BOX (s_sbob_sl64, 3, ((t[3] >> (i * 8)) & 0xff))) ^ \
  l32_from_64 (BOX (s_sbob_sl64, 4, ((t[4] >> (i * 8)) & 0xff))) ^ \
  l32_from_64 (BOX (s_sbob_sl64, 5, ((t[5] >> (i * 8)) & 0xff))) ^ \
  l32_from_64 (BOX (s_sbob_sl64, 6, ((t[6] >> (i * 8)) & 0xff))) ^ \
  l32_from_64 (BOX (s_sbob_sl64, 7, ((t[7] >> (i * 8)) & 0xff)))

// Precomputed round-key schedule for the very first compression, where h == INITVAL.
// In streebog_g the key schedule k depends only on h (via k = LPS(h)) and the round
// constants sbob256_rc64 - the message m never enters k. With h fixed to the Streebog-256
// IV (all bytes 0x01) the whole 13-step schedule is data-independent, so it is hoisted
// here as a constant. sbob256_kc_first[r] == k used in round r (r = 0..11); [12] == the
// final k used in h ^= s ^ k ^ m. This removes 13*64 shared-memory table loads per
// candidate from the first g-call on this LSU-bound kernel. Verified vs. runtime schedule.
CONSTANT_VK u64a sbob256_kc_first[13][8] =
{
  { 0x155f7bb040eec523UL, 0x155f7bb040eec523UL, 0x155f7bb040eec523UL, 0x155f7bb040eec523UL, 0x155f7bb040eec523UL, 0x155f7bb040eec523UL, 0x155f7bb040eec523UL, 0x155f7bb040eec523UL },
  { 0xeaebb276318fee18UL, 0xea4c693382cbd63bUL, 0xbf26be88df699734UL, 0x49a504a9b6fa1c45UL, 0xb1666aa693de22daUL, 0x113563ea5e6b7e9cUL, 0xcdbf01848cd611e6UL, 0xb95e4a9dc30c7d0cUL },
  { 0x919565a231cfa4aaUL, 0x46fde791cec8ae57UL, 0xe3c56411e2de27bfUL, 0x1f9d9e511aba0b94UL, 0x57773e25f11309ceUL, 0x2ce14b67cd005091UL, 0x00fb26ba738ef6c7UL, 0x2d5f800141af74fdUL },
  { 0xf57a17cc650afe61UL, 0x26d3deadafe23502UL, 0xf87b7436229a32a5UL, 0x85459ccaae2842a5UL, 0x0d3a74dda91e80cdUL, 0x330e2b60f01ed098UL, 0x56c16add5dfb6720UL, 0x8692832019310082UL },
  { 0x6f63d34f5f688399UL, 0xa826bf5fb7abd51fUL, 0x3ecb2eaa144393e2UL, 0x4e7d6cc0863c69e4UL, 0x61e175af40d59b16UL, 0xba60d963cd6a540aUL, 0x69bf99c14c3995d5UL, 0x5a3de79f30d5a599UL },
  { 0x25f0e72cae7257f0UL, 0xfdb8c6bc7f9a6c15UL, 0x326e9413d635e7f1UL, 0xeaff2028e5942992UL, 0x1a55b07e905d6162UL, 0x882060860a9970d1UL, 0xe2b0cd223cc898afUL, 0x56a1f7c0137c29beUL },
  { 0x4e6e5462c344d15aUL, 0xb7fb298868e7b346UL, 0x33741921c3e95374UL, 0xacb5e26b0e8d2b0bUL, 0x59f16751b3b69ec8UL, 0xa659593ea405b0b7UL, 0x98408efc8cb1a951UL, 0x8dbbcf819b3df0fcUL },
  { 0x8d0aa21b9aec6c6aUL, 0x2b3534b940a84fb6UL, 0x2a1230d58e638c51UL, 0xc9daefb8e02f3383UL, 0xc709f5a9e5878201UL, 0x6f42d5dc6a746c8dUL, 0x3fb7df9057ada0b0UL, 0xaa6d0139a591f1c1UL },
  { 0xb3a97a7336702199UL, 0x51bd05f743668d8aUL, 0xc50f8f941f5351f3UL, 0xbdd89dee5fa35fe3UL, 0x9c4e220a589d4cbbUL, 0xed49fc69200e2ed8UL, 0x38354437945f7d36UL, 0x0904ddf5a8b68f2bUL },
  { 0x1afa89fcc0636790UL, 0xda9d9eecd88892e6UL, 0xfec3d6bfe830769aUL, 0xafae622e5dc303d7UL, 0x7f7a31a7805db3f0UL, 0x916752f22230f876UL, 0x7b33cb8f67df8fcaUL, 0xd205cb3c39e54fd7UL },
  { 0x648e61636c99ce88UL, 0x8533e43ee0c8a504UL, 0xbb9189e6eee32a4eUL, 0x6edbda389dc2f3bfUL, 0xdf6ddca6e9daa1d6UL, 0xd3962f27af34ce52UL, 0xe1e63f4c628c9c15UL, 0xd5ad89fc0b5c693dUL },
  { 0x0646bda91e280a3eUL, 0x3a6f57000155ec3eUL, 0x579182cf68a16a50UL, 0x382fa3cafc78b976UL, 0x45ca8299c7305fb5UL, 0x778479d865838e62UL, 0x2a119981c6495ae7UL, 0xdbf255760f5a7b1dUL },
  { 0xeb1ab39e4073b2f0UL, 0x22216718aefb32e4UL, 0xf9926a2b4248c862UL, 0x838bd14eb5ba6c3fUL, 0xa33f1ec5ff1cb214UL, 0xdb6aef763e43ff19UL, 0xa17f903ce0f5f90eUL, 0x03bf0065a0ecf9fcUL },
};

DECLSPEC void streebog_g_first (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, LOCAL_AS u64 (*s_sbob_sl64)[256])
{
  u64x s[8];
  u64x t[8];

  for (int i = 0; i < 8; i++)
  {
    s[i] = m[i];
  }

  for (int r = 0; r < 12; r++)
  {
    for (int i = 0; i < 8; i++)
    {
      t[i] = s[i] ^ sbob256_kc_first[r][i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      s[i] = SBOG_LPSti64;
    }
  }

  for (int i = 0; i < 8; i++)
  {
    h[i] ^= s[i] ^ sbob256_kc_first[12][i] ^ m[i];
  }
}

DECLSPEC void streebog_g (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, LOCAL_AS u64 (*s_sbob_sl64)[256])
{
  u64x k[8];
  u64x s[8];
  u64x t[8];

  for (int i = 0; i < 8; i++)
  {
    t[i] = h[i];
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    k[i] = SBOG_LPSti64;
  }

  for (int i = 0; i < 8; i++)
  {
    s[i] = m[i];
  }

  for (int r = 0; r < 12; r++)
  {
    for (int i = 0; i < 8; i++)
    {
      t[i] = s[i] ^ k[i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      s[i] = SBOG_LPSti64;
    }

    for (int i = 0; i < 8; i++)
    {
      t[i] = k[i] ^ sbob256_rc64[r][i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      k[i] = SBOG_LPSti64;
    }
  }

  for (int i = 0; i < 8; i++)
  {
    h[i] ^= s[i] ^ k[i] ^ m[i];
  }
}

// Identical to streebog_g, but specialized for the FINAL compression of a single-block
// candidate: only h[0] and h[1] of the result are consumed (they form r0..r3 in the
// COMPARE). The 12th (last) round therefore needs to produce only output words 0 and 1 of
// the s- and k-chains instead of all 8, which the rolled round loop above cannot prune on
// its own. Value-identical for h[0..1]; drops 2*6*8 = 96 shared s-box loads per candidate.
DECLSPEC void streebog_g_last (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, LOCAL_AS u64 (*s_sbob_sl64)[256])
{
  u64x k[8];
  u64x s[8];
  u64x t[8];

  for (int i = 0; i < 8; i++)
  {
    t[i] = h[i];
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    k[i] = SBOG_LPSti64;
  }

  for (int i = 0; i < 8; i++)
  {
    s[i] = m[i];
  }

  for (int r = 0; r < 10; r++)
  {
    for (int i = 0; i < 8; i++)
    {
      t[i] = s[i] ^ k[i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      s[i] = SBOG_LPSti64;
    }

    for (int i = 0; i < 8; i++)
    {
      t[i] = k[i] ^ sbob256_rc64[r][i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      k[i] = SBOG_LPSti64;
    }
  }

  // Penultimate round (r == 10): the final round consumes only bytes 0 and 1
  // of each output word, so preserve just the low halves of both chains.

  for (int i = 0; i < 8; i++)
  {
    t[i] = s[i] ^ k[i];
  }

  u32x sl[8];

  for (int i = 0; i < 8; i++)
  {
    sl[i] = SBOG_LPSti32;
  }

  for (int i = 0; i < 8; i++)
  {
    t[i] = k[i] ^ sbob256_rc64[10][i];
  }

  u32x kl[8];

  for (int i = 0; i < 8; i++)
  {
    kl[i] = SBOG_LPSti32;
  }

  // Final round (r == 11): only output words 0 and 1 are needed downstream.

  for (int i = 0; i < 8; i++)
  {
    t[i] = (u64x) (sl[i] ^ kl[i]);
  }

  u64x sf[2];

  for (int i = 0; i < 2; i++)
  {
    sf[i] = SBOG_LPSti64;
  }

  for (int i = 0; i < 8; i++)
  {
    t[i] = (u64x) (kl[i] ^ ((u32) sbob256_rc64[11][i]));
  }

  u64x kf[2];

  for (int i = 0; i < 2; i++)
  {
    kf[i] = SBOG_LPSti64;
  }

  h[0] ^= sf[0] ^ kf[0] ^ m[0];
  h[1] ^= sf[1] ^ kf[1] ^ m[1];
}

DECLSPEC void m11700m (LOCAL_AS u64 (*s_sbob_sl64)[256], PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * GOST
     */

    u64x m[8];

    m[0] = hl32_to_64 (w[15], w[14]);
    m[1] = hl32_to_64 (w[13], w[12]);
    m[2] = hl32_to_64 (w[11], w[10]);
    m[3] = hl32_to_64 (w[ 9], w[ 8]);
    m[4] = hl32_to_64 (w[ 7], w[ 6]);
    m[5] = hl32_to_64 (w[ 5], w[ 4]);
    m[6] = hl32_to_64 (w[ 3], w[ 2]);
    m[7] = hl32_to_64 (w[ 1], w0lr );

    m[0] = hc_swap64 (m[0]);
    m[1] = hc_swap64 (m[1]);
    m[2] = hc_swap64 (m[2]);
    m[3] = hc_swap64 (m[3]);
    m[4] = hc_swap64 (m[4]);
    m[5] = hc_swap64 (m[5]);
    m[6] = hc_swap64 (m[6]);
    m[7] = hc_swap64 (m[7]);

    // state buffer (hash)

    u64x h[8];

    h[0] = INITVAL;
    h[1] = INITVAL;
    h[2] = INITVAL;
    h[3] = INITVAL;
    h[4] = INITVAL;
    h[5] = INITVAL;
    h[6] = INITVAL;
    h[7] = INITVAL;

    streebog_g_first (h, m, s_sbob_sl64);

    // Reuse m for the length block so the original vector message is not live
    // across the register-heavy middle compression. Rebuild it afterwards.

    m[0] = 0;
    m[1] = 0;
    m[2] = 0;
    m[3] = 0;
    m[4] = 0;
    m[5] = 0;
    m[6] = 0;
    m[7] = hc_swap64 ((u64) (pw_len * 8));

    streebog_g (h, m, s_sbob_sl64);

    m[0] = hc_swap64 (hl32_to_64 (w[15], w[14]));
    m[1] = hc_swap64 (hl32_to_64 (w[13], w[12]));
    m[2] = hc_swap64 (hl32_to_64 (w[11], w[10]));
    m[3] = hc_swap64 (hl32_to_64 (w[ 9], w[ 8]));
    m[4] = hc_swap64 (hl32_to_64 (w[ 7], w[ 6]));
    m[5] = hc_swap64 (hl32_to_64 (w[ 5], w[ 4]));
    m[6] = hc_swap64 (hl32_to_64 (w[ 3], w[ 2]));
    m[7] = hc_swap64 (hl32_to_64 (w[ 1], w0lr ));

    streebog_g_last (h, m, s_sbob_sl64);

    const u32x r0 = l32_from_64 (h[0]);
    const u32x r1 = h32_from_64 (h[0]);
    const u32x r2 = l32_from_64 (h[1]);
    const u32x r3 = h32_from_64 (h[1]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

DECLSPEC void m11700s (LOCAL_AS u64 (*s_sbob_sl64)[256], PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * GOST
     */

    u64x m[8];

    m[0] = hl32_to_64 (w[15], w[14]);
    m[1] = hl32_to_64 (w[13], w[12]);
    m[2] = hl32_to_64 (w[11], w[10]);
    m[3] = hl32_to_64 (w[ 9], w[ 8]);
    m[4] = hl32_to_64 (w[ 7], w[ 6]);
    m[5] = hl32_to_64 (w[ 5], w[ 4]);
    m[6] = hl32_to_64 (w[ 3], w[ 2]);
    m[7] = hl32_to_64 (w[ 1], w0lr );

    m[0] = hc_swap64 (m[0]);
    m[1] = hc_swap64 (m[1]);
    m[2] = hc_swap64 (m[2]);
    m[3] = hc_swap64 (m[3]);
    m[4] = hc_swap64 (m[4]);
    m[5] = hc_swap64 (m[5]);
    m[6] = hc_swap64 (m[6]);
    m[7] = hc_swap64 (m[7]);

    // state buffer (hash)

    u64x h[8];

    h[0] = INITVAL;
    h[1] = INITVAL;
    h[2] = INITVAL;
    h[3] = INITVAL;
    h[4] = INITVAL;
    h[5] = INITVAL;
    h[6] = INITVAL;
    h[7] = INITVAL;

    streebog_g_first (h, m, s_sbob_sl64);

    // Reuse m for the length block so the original vector message is not live
    // across the register-heavy middle compression. Rebuild it afterwards.

    m[0] = 0;
    m[1] = 0;
    m[2] = 0;
    m[3] = 0;
    m[4] = 0;
    m[5] = 0;
    m[6] = 0;
    m[7] = hc_swap64 ((u64) (pw_len * 8));

    streebog_g (h, m, s_sbob_sl64);

    m[0] = hc_swap64 (hl32_to_64 (w[15], w[14]));
    m[1] = hc_swap64 (hl32_to_64 (w[13], w[12]));
    m[2] = hc_swap64 (hl32_to_64 (w[11], w[10]));
    m[3] = hc_swap64 (hl32_to_64 (w[ 9], w[ 8]));
    m[4] = hc_swap64 (hl32_to_64 (w[ 7], w[ 6]));
    m[5] = hc_swap64 (hl32_to_64 (w[ 5], w[ 4]));
    m[6] = hc_swap64 (hl32_to_64 (w[ 3], w[ 2]));
    m[7] = hc_swap64 (hl32_to_64 (w[ 1], w0lr ));

    streebog_g_last (h, m, s_sbob_sl64);

    const u32x r0 = l32_from_64 (h[0]);
    const u32x r1 = h32_from_64 (h[0]);
    const u32x r2 = l32_from_64 (h[1]);
    const u32x r3 = h32_from_64 (h[1]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m11700_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11700m (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11700_m08 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11700m (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11700_m16 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11700m (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11700_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11700s (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11700_s08 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11700s (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11700_s16 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11700s (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
