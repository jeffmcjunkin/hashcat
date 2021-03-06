/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif

#include "common.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <search.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>

#if defined (_POSIX)
#include <pthread.h>
#include <pwd.h>
#endif // _POSIX

#include "types_int.h"
#include "types.h"
#include "timer.h"
#include "bitops.h"
#include "memory.h"
#include "folder.h"
#include "convert.h"
#include "logging.h"
#include "logfile.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "cpu_aes.h"
#include "cpu_crc32.h"
#include "cpu_des.h"
#include "cpu_md5.h"
#include "cpu_sha1.h"
#include "cpu_sha256.h"
#include "filehandling.h"
#include "opencl.h"
#include "tuningdb.h"
#include "thread.h"
#include "locking.h"
#include "rp_cpu.h"
#include "rp_kernel_on_cpu.h"
#include "terminal.h"
#include "inc_hash_constants.h"
#include "shared.h"
#include "interface.h"
#include "hwmon.h"
#include "mpsp.h"
#include "restore.h"
#include "outfile.h"
#include "potfile.h"
#include "loopback.h"
#include "data.h"
#include "affinity.h"
#include "bitmap.h"
#include "usage.h"
#include "status.h"
#include "hlfmt.h"
#include "filenames.h"
#include "stdout.h"
#include "dictstat.h"
#include "wordlist.h"
#include "version.h"
#include "benchmark.h"
#include "outfile_check.h"
#include "weak_hash.h"
#include "hash_management.h"
#include "remove.h"
#include "debugfile.h"
#include "runtime.h"
#include "attack_mode.h"
#include "kernel.h"
#include "powertune.h"
#include "autotune.h"
#include "induct.h"

extern hc_global_data_t data;

extern int SUPPRESS_OUTPUT;

extern hc_thread_mutex_t mux_hwmon;
extern hc_thread_mutex_t mux_display;

extern void (*get_next_word_func) (char *, u32, u32 *, u32 *);

extern const unsigned int full01;
extern const unsigned int full80;

extern const int DEFAULT_BENCHMARK_ALGORITHMS_BUF[];

static const char PROGNAME[] = "hashcat";

const int comptime = COMPTIME;

#define FORCE 0




// outfile_check
#define OUTFILE_CHECK_TIMER     5


// weak_hash
#define WEAK_HASH_THRESHOLD     100

// hash_management
#define USERNAME                0
int sort_by_digest_p0p1 (const void *v1, const void *v2)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  const uint dgst_pos0 = data.hashconfig->dgst_pos0;
  const uint dgst_pos1 = data.hashconfig->dgst_pos1;
  const uint dgst_pos2 = data.hashconfig->dgst_pos2;
  const uint dgst_pos3 = data.hashconfig->dgst_pos3;

  if (d1[dgst_pos3] > d2[dgst_pos3]) return ( 1);
  if (d1[dgst_pos3] < d2[dgst_pos3]) return -1;
  if (d1[dgst_pos2] > d2[dgst_pos2]) return ( 1);
  if (d1[dgst_pos2] < d2[dgst_pos2]) return -1;
  if (d1[dgst_pos1] > d2[dgst_pos1]) return ( 1);
  if (d1[dgst_pos1] < d2[dgst_pos1]) return -1;
  if (d1[dgst_pos0] > d2[dgst_pos0]) return ( 1);
  if (d1[dgst_pos0] < d2[dgst_pos0]) return -1;

  return 0;
}
int sort_by_salt (const void *v1, const void *v2)
{
  const salt_t *s1 = (const salt_t *) v1;
  const salt_t *s2 = (const salt_t *) v2;

  const int res1 = s1->salt_len - s2->salt_len;

  if (res1 != 0) return (res1);

  const int res2 = s1->salt_iter - s2->salt_iter;

  if (res2 != 0) return (res2);

  uint n;

  n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  n = 8;

  while (n--)
  {
    if (s1->salt_buf_pc[n] > s2->salt_buf_pc[n]) return ( 1);
    if (s1->salt_buf_pc[n] < s2->salt_buf_pc[n]) return -1;
  }

  return 0;
}
int sort_by_hash (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  if (data.hashconfig->is_salted)
  {
    const salt_t *s1 = h1->salt;
    const salt_t *s2 = h2->salt;

    int res = sort_by_salt (s1, s2);

    if (res != 0) return (res);
  }

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return sort_by_digest_p0p1 (d1, d2);
}
int sort_by_hash_no_salt (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return sort_by_digest_p0p1 (d1, d2);
}


// remove
#define REMOVE                  0
#define REMOVE_TIMER            60

// debug_mode
#define DEBUG_MODE              0
typedef struct
{
  FILE *fp;

} debug_ctx_t;
void debug_format_plain (debug_ctx_t *debug_ctx, const unsigned char *plain_ptr, const uint plain_len)
{
  int needs_hexify = 0;

  for (uint i = 0; i < plain_len; i++)
  {
    if (plain_ptr[i] < 0x20)
    {
      needs_hexify = 1;

      break;
    }

    if (plain_ptr[i] > 0x7f)
    {
      needs_hexify = 1;

      break;
    }
  }

  if (needs_hexify == 1)
  {
    fprintf (debug_ctx->fp, "$HEX[");

    for (uint i = 0; i < plain_len; i++)
    {
      fprintf (debug_ctx->fp, "%02x", plain_ptr[i]);
    }

    fprintf (debug_ctx->fp, "]");
  }
  else
  {
    fwrite (plain_ptr, plain_len, 1, debug_ctx->fp);
  }
}
void format_debug (char *debug_file, uint debug_mode, unsigned char *orig_plain_ptr, uint orig_plain_len, unsigned char *mod_plain_ptr, uint mod_plain_len, char *rule_buf, int rule_len)
{
  unsigned char *rule_ptr = (unsigned char *) rule_buf;

  debug_ctx_t debug_ctx;

  debug_ctx.fp = fopen (debug_file, "ab");

  if (debug_ctx.fp == NULL)
  {
    log_error ("ERROR: Could not open debug-file for writing");

    return;
  }

  if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
  {
    debug_format_plain (&debug_ctx, orig_plain_ptr, orig_plain_len);

    if ((debug_mode == 3) || (debug_mode == 4)) fputc (':', debug_ctx.fp);
  }

  fwrite (rule_ptr, rule_len, 1, debug_ctx.fp);

  if (debug_mode == 4)
  {
    fputc (':', debug_ctx.fp);

    debug_format_plain (&debug_ctx, mod_plain_ptr, mod_plain_len);
  }

  fputc  ('\n', debug_ctx.fp);

  fclose (debug_ctx.fp);
}

// runtime
#define RUNTIME                 0

// attack_mode
#define ATTACK_MODE             0

// kernel
#define KERNEL_ACCEL            0
#define KERNEL_LOOPS            0
#define KERNEL_RULES            1024
#define KERNEL_COMBS            1024
#define KERNEL_BFS              1024
#define KERNEL_THREADS_MAX      256
#define KERNEL_THREADS_MAX_CPU  1
#define WORKLOAD_PROFILE        2
#define SCRYPT_TMTO             0
#define NVIDIA_SPIN_DAMP        100
static const char OPTI_STR_ZERO_BYTE[]         = "Zero-Byte";
static const char OPTI_STR_PRECOMPUTE_INIT[]   = "Precompute-Init";
static const char OPTI_STR_PRECOMPUTE_MERKLE[] = "Precompute-Merkle-Demgard";
static const char OPTI_STR_PRECOMPUTE_PERMUT[] = "Precompute-Final-Permutation";
static const char OPTI_STR_MEET_IN_MIDDLE[]    = "Meet-In-The-Middle";
static const char OPTI_STR_EARLY_SKIP[]        = "Early-Skip";
static const char OPTI_STR_NOT_SALTED[]        = "Not-Salted";
static const char OPTI_STR_NOT_ITERATED[]      = "Not-Iterated";
static const char OPTI_STR_PREPENDED_SALT[]    = "Prepended-Salt";
static const char OPTI_STR_APPENDED_SALT[]     = "Appended-Salt";
static const char OPTI_STR_SINGLE_HASH[]       = "Single-Hash";
static const char OPTI_STR_SINGLE_SALT[]       = "Single-Salt";
static const char OPTI_STR_BRUTE_FORCE[]       = "Brute-Force";
static const char OPTI_STR_RAW_HASH[]          = "Raw-Hash";
static const char OPTI_STR_SLOW_HASH_SIMD[]    = "Slow-Hash-SIMD";
static const char OPTI_STR_USES_BITS_8[]       = "Uses-8-Bit";
static const char OPTI_STR_USES_BITS_16[]      = "Uses-16-Bit";
static const char OPTI_STR_USES_BITS_32[]      = "Uses-32-Bit";
static const char OPTI_STR_USES_BITS_64[]      = "Uses-64-Bit";
static char *stroptitype (const uint opti_type)
{
  switch (opti_type)
  {
    case OPTI_TYPE_ZERO_BYTE:         return ((char *) OPTI_STR_ZERO_BYTE);
    case OPTI_TYPE_PRECOMPUTE_INIT:   return ((char *) OPTI_STR_PRECOMPUTE_INIT);
    case OPTI_TYPE_PRECOMPUTE_MERKLE: return ((char *) OPTI_STR_PRECOMPUTE_MERKLE);
    case OPTI_TYPE_PRECOMPUTE_PERMUT: return ((char *) OPTI_STR_PRECOMPUTE_PERMUT);
    case OPTI_TYPE_MEET_IN_MIDDLE:    return ((char *) OPTI_STR_MEET_IN_MIDDLE);
    case OPTI_TYPE_EARLY_SKIP:        return ((char *) OPTI_STR_EARLY_SKIP);
    case OPTI_TYPE_NOT_SALTED:        return ((char *) OPTI_STR_NOT_SALTED);
    case OPTI_TYPE_NOT_ITERATED:      return ((char *) OPTI_STR_NOT_ITERATED);
    case OPTI_TYPE_PREPENDED_SALT:    return ((char *) OPTI_STR_PREPENDED_SALT);
    case OPTI_TYPE_APPENDED_SALT:     return ((char *) OPTI_STR_APPENDED_SALT);
    case OPTI_TYPE_SINGLE_HASH:       return ((char *) OPTI_STR_SINGLE_HASH);
    case OPTI_TYPE_SINGLE_SALT:       return ((char *) OPTI_STR_SINGLE_SALT);
    case OPTI_TYPE_BRUTE_FORCE:       return ((char *) OPTI_STR_BRUTE_FORCE);
    case OPTI_TYPE_RAW_HASH:          return ((char *) OPTI_STR_RAW_HASH);
    case OPTI_TYPE_SLOW_HASH_SIMD:    return ((char *) OPTI_STR_SLOW_HASH_SIMD);
    case OPTI_TYPE_USES_BITS_8:       return ((char *) OPTI_STR_USES_BITS_8);
    case OPTI_TYPE_USES_BITS_16:      return ((char *) OPTI_STR_USES_BITS_16);
    case OPTI_TYPE_USES_BITS_32:      return ((char *) OPTI_STR_USES_BITS_32);
    case OPTI_TYPE_USES_BITS_64:      return ((char *) OPTI_STR_USES_BITS_64);
  }

  return (NULL);
}

// powertune
#define POWERTUNE_ENABLE        0

// autotune
#define OPENCL_VECTOR_WIDTH     0
static double TARGET_MS_PROFILE[4] = { 2, 12, 96, 480 };

// induct
#define INDUCT_DIR              "induct"
int sort_by_mtime (const void *p1, const void *p2)
{
  const char **f1 = (const char **) p1;
  const char **f2 = (const char **) p2;

  struct stat s1; stat (*f1, &s1);
  struct stat s2; stat (*f2, &s2);

  return s2.st_mtime - s1.st_mtime;
}

// thread
static hc_thread_mutex_t mux_dispatcher;
static hc_thread_mutex_t mux_counter;


// restore
static void check_checkpoint ()
{
  // if (data.restore_disable == 1) break;  (this is already implied by previous checks)

  u64 words_cur = get_lowest_words_done ();

  if (words_cur != data.checkpoint_cur_words)
  {
    myabort ();
  }
}


// data
#define global_free(attr)       \
{                               \
  myfree ((void *) data.attr);  \
                                \
  data.attr = NULL;             \
}

#define local_free(attr)  \
{                         \
  myfree ((void *) attr); \
                          \
  attr = NULL;            \
}




























static void check_hash (hc_device_param_t *device_param, plain_t *plain)
{
  uint  quiet      = data.quiet;
  uint  debug_mode = data.debug_mode;
  char *debug_file = data.debug_file;

  char debug_rule_buf[BLOCK_SIZE] = { 0 };
  int  debug_rule_len  = 0; // -1 error
  uint debug_plain_len = 0;

  u8 debug_plain_ptr[BLOCK_SIZE] = { 0 };

  // hash

  char out_buf[HCBUFSIZ_LARGE] = { 0 };

  const u32 salt_pos    = plain->salt_pos;
  const u32 digest_pos  = plain->digest_pos;  // relative
  const u32 gidvid      = plain->gidvid;
  const u32 il_pos      = plain->il_pos;

  hashconfig_t *hashconfig  = data.hashconfig;
  void         *digests_buf = data.digests_buf;
  salt_t       *salts_buf   = data.salts_buf;
  void         *esalts_buf  = data.esalts_buf;
  hashinfo_t  **hash_info   = data.hash_info;
  char         *hashfile    = data.hashfile;

  ascii_digest (out_buf, salt_pos, digest_pos, hashconfig, digests_buf, salts_buf, esalts_buf, hash_info, hashfile);

  // plain

  u64 crackpos = device_param->words_off;

  uint plain_buf[16] = { 0 };

  u8 *plain_ptr = (u8 *) plain_buf;

  unsigned int plain_len = 0;

  if (data.attack_mode == ATTACK_MODE_STRAIGHT)
  {
    pw_t pw;

    gidd_to_pw_t (device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    const uint off = device_param->innerloop_pos + il_pos;

    if (debug_mode > 0)
    {
      debug_rule_len = 0;

      // save rule
      if ((debug_mode == 1) || (debug_mode == 3) || (debug_mode == 4))
      {
        memset (debug_rule_buf, 0, sizeof (debug_rule_buf));

        debug_rule_len = kernel_rule_to_cpu_rule (debug_rule_buf, &data.kernel_rules_buf[off]);
      }

      // save plain
      if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
      {
        memset (debug_plain_ptr, 0, sizeof (debug_plain_ptr));

        memcpy (debug_plain_ptr, plain_ptr, plain_len);

        debug_plain_len = plain_len;
      }
    }

    plain_len = apply_rules (data.kernel_rules_buf[off].cmds, &plain_buf[0], &plain_buf[4], plain_len);

    crackpos += gidvid;
    crackpos *= data.kernel_rules_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (plain_len > data.pw_max) plain_len = data.pw_max;
  }
  else if (data.attack_mode == ATTACK_MODE_COMBI)
  {
    pw_t pw;

    gidd_to_pw_t (device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
    uint  comb_len =          device_param->combs_buf[il_pos].pw_len;

    if (data.combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      memcpy (plain_ptr + plain_len, comb_buf, comb_len);
    }
    else
    {
      memmove (plain_ptr + comb_len, plain_ptr, plain_len);

      memcpy (plain_ptr, comb_buf, comb_len);
    }

    plain_len += comb_len;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }
  else if (data.attack_mode == ATTACK_MODE_BF)
  {
    u64 l_off = device_param->kernel_params_mp_l_buf64[3] + gidvid;
    u64 r_off = device_param->kernel_params_mp_r_buf64[3] + il_pos;

    uint l_start = device_param->kernel_params_mp_l_buf32[5];
    uint r_start = device_param->kernel_params_mp_r_buf32[5];

    uint l_stop = device_param->kernel_params_mp_l_buf32[4];
    uint r_stop = device_param->kernel_params_mp_r_buf32[4];

    sp_exec (l_off, (char *) plain_ptr + l_start, data.root_css_buf, data.markov_css_buf, l_start, l_start + l_stop);
    sp_exec (r_off, (char *) plain_ptr + r_start, data.root_css_buf, data.markov_css_buf, r_start, r_start + r_stop);

    plain_len = data.css_cnt;

    crackpos += gidvid;
    crackpos *= data.bfs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;
  }
  else if (data.attack_mode == ATTACK_MODE_HYBRID1)
  {
    pw_t pw;

    gidd_to_pw_t (device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

    uint start = 0;
    uint stop  = device_param->kernel_params_mp_buf32[4];

    sp_exec (off, (char *) plain_ptr + plain_len, data.root_css_buf, data.markov_css_buf, start, start + stop);

    plain_len += start + stop;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }
  else if (data.attack_mode == ATTACK_MODE_HYBRID2)
  {
    pw_t pw;

    gidd_to_pw_t (device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = pw.pw_len;

    u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

    uint start = 0;
    uint stop  = device_param->kernel_params_mp_buf32[4];

    memmove (plain_ptr + stop, plain_ptr, plain_len);

    sp_exec (off, (char *) plain_ptr, data.root_css_buf, data.markov_css_buf, start, start + stop);

    plain_len += start + stop;

    crackpos += gidvid;
    crackpos *= data.combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;

    if (data.pw_max != PW_DICTMAX1)
    {
      if (plain_len > data.pw_max) plain_len = data.pw_max;
    }
  }

  if (data.attack_mode == ATTACK_MODE_BF)
  {
    if (hashconfig->opti_type & OPTI_TYPE_BRUTE_FORCE) // lots of optimizations can happen here
    {
      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          plain_len = plain_len - data.salts_buf[0].salt_len;
        }
      }

      if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
      {
        for (uint i = 0, j = 0; i < plain_len; i += 2, j += 1)
        {
          plain_ptr[j] = plain_ptr[i];
        }

        plain_len = plain_len / 2;
      }
    }
  }

  // if enabled, update also the potfile
  // no need for locking, we're in a mutex protected function

  potfile_ctx_t *potfile_ctx = data.potfile_ctx;

  if (potfile_ctx->fp)
  {
    potfile_write_append (potfile_ctx, out_buf, plain_ptr, plain_len);
  }

  // outfile, can be either to file or stdout
  // if an error occurs opening the file, send to stdout as fallback
  // the fp gets opened for each cracked hash so that the user can modify (move) the outfile while hashcat runs

  outfile_ctx_t *outfile_ctx = data.outfile_ctx;

  outfile_write_open (outfile_ctx);

  if (outfile_ctx->filename == NULL) if (quiet == 0) clear_prompt ();

  outfile_write (outfile_ctx, out_buf, plain_ptr, plain_len, crackpos, NULL, 0, hashconfig);

  outfile_write_close (outfile_ctx);

  if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
  {
    if ((data.devices_status != STATUS_CRACKED) && (data.status != 1))
    {
      if (outfile_ctx->filename == NULL) if (quiet == 0) send_prompt ();
    }
  }

  // if enabled, update also the loopback file

  loopback_ctx_t *loopback_ctx = data.loopback_ctx;

  if (loopback_ctx->fp)
  {
    loopback_write_append (loopback_ctx, plain_ptr, plain_len);
  }

  // (rule) debug mode

  // the next check implies that:
  // - (data.attack_mode == ATTACK_MODE_STRAIGHT)
  // - debug_mode > 0

  if ((debug_plain_len > 0) || (debug_rule_len > 0))
  {
    if (debug_rule_len < 0) debug_rule_len = 0;

    if ((quiet == 0) && (debug_file == NULL)) clear_prompt ();

    format_debug (debug_file, debug_mode, debug_plain_ptr, debug_plain_len, plain_ptr, plain_len, debug_rule_buf, debug_rule_len);

    if ((quiet == 0) && (debug_file == NULL))
    {
      send_prompt ();
    }
  }
}

static int check_cracked (hc_device_param_t *device_param, const uint salt_pos, hashconfig_t *hashconfig)
{
  salt_t *salt_buf = &data.salts_buf[salt_pos];

  u32 num_cracked;

  cl_int CL_err;

  CL_err = hc_clEnqueueReadBuffer (data.ocl, device_param->command_queue, device_param->d_result, CL_TRUE, 0, sizeof (u32), &num_cracked, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  if (num_cracked)
  {
    // display hack (for weak hashes etc, it could be that there is still something to clear on the current line)

    log_info_nn ("");

    plain_t *cracked = (plain_t *) mycalloc (num_cracked, sizeof (plain_t));

    CL_err = hc_clEnqueueReadBuffer (data.ocl, device_param->command_queue, device_param->d_plain_bufs, CL_TRUE, 0, num_cracked * sizeof (plain_t), cracked, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }

    uint cpt_cracked = 0;

    hc_thread_mutex_lock (mux_display);

    for (uint i = 0; i < num_cracked; i++)
    {
      const uint hash_pos = cracked[i].hash_pos;

      if (data.digests_shown[hash_pos] == 1) continue;

      if ((hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK) == 0)
      {
        data.digests_shown[hash_pos] = 1;

        data.digests_done++;

        cpt_cracked++;

        salt_buf->digests_done++;

        if (salt_buf->digests_done == salt_buf->digests_cnt)
        {
          data.salts_shown[salt_pos] = 1;

          data.salts_done++;
        }
      }

      if (data.salts_done == data.salts_cnt) data.devices_status = STATUS_CRACKED;

      check_hash (device_param, &cracked[i]);
    }

    hc_thread_mutex_unlock (mux_display);

    myfree (cracked);

    if (cpt_cracked > 0)
    {
      hc_thread_mutex_lock (mux_display);

      data.cpt_buf[data.cpt_pos].timestamp = time (NULL);
      data.cpt_buf[data.cpt_pos].cracked   = cpt_cracked;

      data.cpt_pos++;

      data.cpt_total += cpt_cracked;

      if (data.cpt_pos == CPT_BUF) data.cpt_pos = 0;

      hc_thread_mutex_unlock (mux_display);
    }

    if (hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK)
    {
      // we need to reset cracked state on the device
      // otherwise host thinks again and again the hash was cracked
      // and returns invalid password each time

      memset (data.digests_shown_tmp, 0, salt_buf->digests_cnt * sizeof (uint));

      CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_digests_shown, CL_TRUE, salt_buf->digests_offset * sizeof (uint), salt_buf->digests_cnt * sizeof (uint), &data.digests_shown_tmp[salt_buf->digests_offset], 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }
    }

    num_cracked = 0;

    CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_result, CL_TRUE, 0, sizeof (u32), &num_cracked, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }

  return 0;
}

static void save_hash ()
{
  hashconfig_t *hashconfig  = data.hashconfig;
  void         *digests_buf = data.digests_buf;
  salt_t       *salts_buf   = data.salts_buf;
  void         *esalts_buf  = data.esalts_buf;
  hashinfo_t  **hash_info   = data.hash_info;
  char         *hashfile    = data.hashfile;

  char new_hashfile[256] = { 0 };
  char old_hashfile[256] = { 0 };

  snprintf (new_hashfile, 255, "%s.new", hashfile);
  snprintf (old_hashfile, 255, "%s.old", hashfile);

  unlink (new_hashfile);

  char separator = hashconfig->separator;

  FILE *fp = fopen (new_hashfile, "wb");

  if (fp == NULL)
  {
    log_error ("ERROR: %s: %s", new_hashfile, strerror (errno));

    exit (-1);
  }

  for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
  {
    if (data.salts_shown[salt_pos] == 1) continue;

    salt_t *salt_buf = &data.salts_buf[salt_pos];

    for (uint digest_pos = 0; digest_pos < salt_buf->digests_cnt; digest_pos++)
    {
      uint idx = salt_buf->digests_offset + digest_pos;

      if (data.digests_shown[idx] == 1) continue;

      if (hashconfig->hash_mode != 2500)
      {
        if (data.username == 1)
        {
          user_t *user = data.hash_info[idx]->user;

          uint i;

          for (i = 0; i < user->user_len; i++) fputc (user->user_name[i], fp);

          fputc (separator, fp);
        }

        char out_buf[HCBUFSIZ_LARGE]; // scratch buffer

        out_buf[0] = 0;

        ascii_digest (out_buf, salt_pos, digest_pos, hashconfig, digests_buf, salts_buf, esalts_buf, hash_info, hashfile);

        fputs (out_buf, fp);

        fputc ('\n', fp);
      }
      else
      {
        hccap_t hccap;

        to_hccap_t (&hccap, salt_pos, digest_pos, hashconfig, digests_buf, salts_buf, esalts_buf);

        fwrite (&hccap, sizeof (hccap_t), 1, fp);
      }
    }
  }

  fflush (fp);

  fclose (fp);

  unlink (old_hashfile);

  if (rename (hashfile, old_hashfile) != 0)
  {
    log_error ("ERROR: Rename file '%s' to '%s': %s", hashfile, old_hashfile, strerror (errno));

    exit (-1);
  }

  unlink (hashfile);

  if (rename (new_hashfile, hashfile) != 0)
  {
    log_error ("ERROR: Rename file '%s' to '%s': %s", new_hashfile, hashfile, strerror (errno));

    exit (-1);
  }

  unlink (old_hashfile);
}

static int run_kernel (const uint kern_run, hc_device_param_t *device_param, const uint num, const uint event_update, const uint iteration, hashconfig_t *hashconfig)
{
  cl_int CL_err = CL_SUCCESS;

  uint num_elements = num;

  device_param->kernel_params_buf32[33] = data.combs_mode;
  device_param->kernel_params_buf32[34] = num;

  uint kernel_threads = device_param->kernel_threads;

  while (num_elements % kernel_threads) num_elements++;

  cl_kernel kernel = NULL;

  switch (kern_run)
  {
    case KERN_RUN_1:    kernel = device_param->kernel1;     break;
    case KERN_RUN_12:   kernel = device_param->kernel12;    break;
    case KERN_RUN_2:    kernel = device_param->kernel2;     break;
    case KERN_RUN_23:   kernel = device_param->kernel23;    break;
    case KERN_RUN_3:    kernel = device_param->kernel3;     break;
  }

  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 24, sizeof (cl_uint), device_param->kernel_params[24]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 25, sizeof (cl_uint), device_param->kernel_params[25]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 26, sizeof (cl_uint), device_param->kernel_params[26]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 27, sizeof (cl_uint), device_param->kernel_params[27]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 28, sizeof (cl_uint), device_param->kernel_params[28]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 29, sizeof (cl_uint), device_param->kernel_params[29]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 30, sizeof (cl_uint), device_param->kernel_params[30]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 31, sizeof (cl_uint), device_param->kernel_params[31]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 32, sizeof (cl_uint), device_param->kernel_params[32]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 33, sizeof (cl_uint), device_param->kernel_params[33]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 34, sizeof (cl_uint), device_param->kernel_params[34]);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  cl_event event;

  if ((hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE) && (data.attack_mode == ATTACK_MODE_BF))
  {
    const size_t global_work_size[3] = { num_elements,        32, 1 };
    const size_t local_work_size[3]  = { kernel_threads / 32, 32, 1 };

    CL_err = hc_clEnqueueNDRangeKernel (data.ocl, device_param->command_queue, kernel, 2, NULL, global_work_size, local_work_size, 0, NULL, &event);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }
  else
  {
    if (kern_run == KERN_RUN_2)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD)
      {
        num_elements = CEIL (num_elements / device_param->vector_width);
      }
    }

    while (num_elements % kernel_threads) num_elements++;

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    CL_err = hc_clEnqueueNDRangeKernel (data.ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, &event);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }

  CL_err = hc_clFlush (data.ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  if (device_param->nvidia_spin_damp > 0)
  {
    if (data.devices_status == STATUS_RUNNING)
    {
      if (iteration < EXPECTED_ITERATIONS)
      {
        switch (kern_run)
        {
          case KERN_RUN_1: if (device_param->exec_us_prev1[iteration] > 0) usleep ((useconds_t)(device_param->exec_us_prev1[iteration] * device_param->nvidia_spin_damp)); break;
          case KERN_RUN_2: if (device_param->exec_us_prev2[iteration] > 0) usleep ((useconds_t)(device_param->exec_us_prev2[iteration] * device_param->nvidia_spin_damp)); break;
          case KERN_RUN_3: if (device_param->exec_us_prev3[iteration] > 0) usleep ((useconds_t)(device_param->exec_us_prev3[iteration] * device_param->nvidia_spin_damp)); break;
        }
      }
    }
  }

  CL_err = hc_clWaitForEvents (data.ocl, 1, &event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clWaitForEvents(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  cl_ulong time_start;
  cl_ulong time_end;

  CL_err |= hc_clGetEventProfilingInfo (data.ocl, event, CL_PROFILING_COMMAND_START, sizeof (time_start), &time_start, NULL);
  CL_err |= hc_clGetEventProfilingInfo (data.ocl, event, CL_PROFILING_COMMAND_END,   sizeof (time_end),   &time_end,   NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clGetEventProfilingInfo(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  const double exec_us = (double) (time_end - time_start) / 1000;

  if (data.devices_status == STATUS_RUNNING)
  {
    if (iteration < EXPECTED_ITERATIONS)
    {
      switch (kern_run)
      {
        case KERN_RUN_1: device_param->exec_us_prev1[iteration] = exec_us; break;
        case KERN_RUN_2: device_param->exec_us_prev2[iteration] = exec_us; break;
        case KERN_RUN_3: device_param->exec_us_prev3[iteration] = exec_us; break;
      }
    }
  }

  if (event_update)
  {
    uint exec_pos = device_param->exec_pos;

    device_param->exec_ms[exec_pos] = exec_us / 1000;

    exec_pos++;

    if (exec_pos == EXEC_CACHE)
    {
      exec_pos = 0;
    }

    device_param->exec_pos = exec_pos;
  }

  CL_err = hc_clReleaseEvent (data.ocl, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clReleaseEvent(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFinish (data.ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

static int run_kernel_mp (const uint kern_run, hc_device_param_t *device_param, const uint num)
{
  cl_int CL_err = CL_SUCCESS;

  uint num_elements = num;

  switch (kern_run)
  {
    case KERN_RUN_MP:   device_param->kernel_params_mp_buf32[8]   = num; break;
    case KERN_RUN_MP_R: device_param->kernel_params_mp_r_buf32[8] = num; break;
    case KERN_RUN_MP_L: device_param->kernel_params_mp_l_buf32[9] = num; break;
  }

  // causes problems with special threads like in bcrypt
  // const uint kernel_threads = device_param->kernel_threads;

  uint kernel_threads = device_param->kernel_threads;

  while (num_elements % kernel_threads) num_elements++;

  cl_kernel kernel = NULL;

  switch (kern_run)
  {
    case KERN_RUN_MP:   kernel = device_param->kernel_mp;   break;
    case KERN_RUN_MP_R: kernel = device_param->kernel_mp_r; break;
    case KERN_RUN_MP_L: kernel = device_param->kernel_mp_l; break;
  }

  switch (kern_run)
  {
    case KERN_RUN_MP:   CL_err |= hc_clSetKernelArg (data.ocl, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp[3]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp[4]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp[5]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp[6]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp[7]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 8, sizeof (cl_uint),  device_param->kernel_params_mp[8]);
                        break;
    case KERN_RUN_MP_R: CL_err |= hc_clSetKernelArg (data.ocl, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp_r[3]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp_r[4]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp_r[5]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp_r[6]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp_r[7]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 8, sizeof (cl_uint),  device_param->kernel_params_mp_r[8]);
                        break;
    case KERN_RUN_MP_L: CL_err |= hc_clSetKernelArg (data.ocl, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp_l[3]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp_l[4]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp_l[5]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp_l[6]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp_l[7]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 8, sizeof (cl_uint),  device_param->kernel_params_mp_l[8]);
                        CL_err |= hc_clSetKernelArg (data.ocl, kernel, 9, sizeof (cl_uint),  device_param->kernel_params_mp_l[9]);
                        break;
  }

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  const size_t global_work_size[3] = { num_elements,   1, 1 };
  const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

  CL_err = hc_clEnqueueNDRangeKernel (data.ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFlush (data.ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFinish (data.ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

static int run_kernel_tm (hc_device_param_t *device_param)
{
  cl_int CL_err = CL_SUCCESS;

  const uint num_elements = 1024; // fixed

  uint kernel_threads = 32;

  cl_kernel kernel = device_param->kernel_tm;

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  CL_err = hc_clEnqueueNDRangeKernel (data.ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFlush (data.ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFinish (data.ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

static int run_kernel_amp (hc_device_param_t *device_param, const uint num)
{
  cl_int CL_err = CL_SUCCESS;

  uint num_elements = num;

  device_param->kernel_params_amp_buf32[5] = data.combs_mode;
  device_param->kernel_params_amp_buf32[6] = num_elements;

  // causes problems with special threads like in bcrypt
  // const uint kernel_threads = device_param->kernel_threads;

  uint kernel_threads = device_param->kernel_threads;

  while (num_elements % kernel_threads) num_elements++;

  cl_kernel kernel = device_param->kernel_amp;

  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 5, sizeof (cl_uint), device_param->kernel_params_amp[5]);
  CL_err |= hc_clSetKernelArg (data.ocl, kernel, 6, sizeof (cl_uint), device_param->kernel_params_amp[6]);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  CL_err = hc_clEnqueueNDRangeKernel (data.ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFlush (data.ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFinish (data.ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

static int run_kernel_memset (hc_device_param_t *device_param, cl_mem buf, const uint value, const uint num)
{
  cl_int CL_err = CL_SUCCESS;

  const u32 num16d = num / 16;
  const u32 num16m = num % 16;

  if (num16d)
  {
    device_param->kernel_params_memset_buf32[1] = value;
    device_param->kernel_params_memset_buf32[2] = num16d;

    uint kernel_threads = device_param->kernel_threads;

    uint num_elements = num16d;

    while (num_elements % kernel_threads) num_elements++;

    cl_kernel kernel = device_param->kernel_memset;

    CL_err |= hc_clSetKernelArg (data.ocl, kernel, 0, sizeof (cl_mem),  (void *) &buf);
    CL_err |= hc_clSetKernelArg (data.ocl, kernel, 1, sizeof (cl_uint), device_param->kernel_params_memset[1]);
    CL_err |= hc_clSetKernelArg (data.ocl, kernel, 2, sizeof (cl_uint), device_param->kernel_params_memset[2]);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    CL_err = hc_clEnqueueNDRangeKernel (data.ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }

    CL_err = hc_clFlush (data.ocl, device_param->command_queue);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }

    CL_err = hc_clFinish (data.ocl, device_param->command_queue);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }

  if (num16m)
  {
    u32 tmp[4];

    tmp[0] = value;
    tmp[1] = value;
    tmp[2] = value;
    tmp[3] = value;

    CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, buf, CL_TRUE, num16d * 16, num16m, tmp, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }

  return 0;
}

static int run_kernel_bzero (hc_device_param_t *device_param, cl_mem buf, const size_t size)
{
  return run_kernel_memset (device_param, buf, 0, size);
}

static int choose_kernel (hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint attack_exec, const uint attack_mode, const uint opts_type, const salt_t *salt_buf, const uint highest_pw_len, const uint pws_cnt, const uint fast_iteration)
{
  cl_int CL_err = CL_SUCCESS;

  if (hashconfig->hash_mode == 2000)
  {
    process_stdout (device_param, pws_cnt);

    return 0;
  }

  if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (attack_mode == ATTACK_MODE_BF)
    {
      if (opts_type & OPTS_TYPE_PT_BITSLICE)
      {
        const uint size_tm = 32 * sizeof (bs_word_t);

        run_kernel_bzero (device_param, device_param->d_tm_c, size_tm);

        run_kernel_tm (device_param);

        CL_err = hc_clEnqueueCopyBuffer (data.ocl, device_param->command_queue, device_param->d_tm_c, device_param->d_bfs_c, 0, 0, size_tm, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
    }

    if (highest_pw_len < 16)
    {
      run_kernel (KERN_RUN_1, device_param, pws_cnt, true, fast_iteration, hashconfig);
    }
    else if (highest_pw_len < 32)
    {
      run_kernel (KERN_RUN_2, device_param, pws_cnt, true, fast_iteration, hashconfig);
    }
    else
    {
      run_kernel (KERN_RUN_3, device_param, pws_cnt, true, fast_iteration, hashconfig);
    }
  }
  else
  {
    run_kernel_amp (device_param, pws_cnt);

    run_kernel (KERN_RUN_1, device_param, pws_cnt, false, 0, hashconfig);

    if (opts_type & OPTS_TYPE_HOOK12)
    {
      run_kernel (KERN_RUN_12, device_param, pws_cnt, false, 0, hashconfig);

      CL_err = hc_clEnqueueReadBuffer (data.ocl, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      // do something with data

      CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }
    }

    uint iter = salt_buf->salt_iter;

    uint loop_step = device_param->kernel_loops;

    for (uint loop_pos = 0, slow_iteration = 0; loop_pos < iter; loop_pos += loop_step, slow_iteration++)
    {
      uint loop_left = iter - loop_pos;

      loop_left = MIN (loop_left, loop_step);

      device_param->kernel_params_buf32[28] = loop_pos;
      device_param->kernel_params_buf32[29] = loop_left;

      run_kernel (KERN_RUN_2, device_param, pws_cnt, true, slow_iteration, hashconfig);

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;

      /**
       * speed
       */

      const float iter_part = (float) (loop_pos + loop_left) / iter;

      const u64 perf_sum_all = (u64) (pws_cnt * iter_part);

      double speed_ms;

      hc_timer_get (device_param->timer_speed, speed_ms);

      const u32 speed_pos = device_param->speed_pos;

      device_param->speed_cnt[speed_pos] = perf_sum_all;

      device_param->speed_ms[speed_pos] = speed_ms;

      if (data.benchmark == 1)
      {
        if (speed_ms > 4096) data.devices_status = STATUS_ABORTED;
      }
    }

    if (opts_type & OPTS_TYPE_HOOK23)
    {
      run_kernel (KERN_RUN_23, device_param, pws_cnt, false, 0, hashconfig);

      CL_err = hc_clEnqueueReadBuffer (data.ocl, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      // do something with data

      CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }
    }

    run_kernel (KERN_RUN_3, device_param, pws_cnt, false, 0, hashconfig);
  }

  return 0;
}

static int run_copy (hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint pws_cnt)
{
  cl_int CL_err = CL_SUCCESS;

  if (data.attack_kern == ATTACK_KERN_STRAIGHT)
  {
    CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_pws_buf, CL_TRUE, 0, pws_cnt * sizeof (pw_t), device_param->pws_buf, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }
  else if (data.attack_kern == ATTACK_KERN_COMBI)
  {
    if (data.attack_mode == ATTACK_MODE_COMBI)
    {
      if (data.combs_mode == COMBINATOR_MODE_BASE_RIGHT)
      {
        if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
        {
          for (u32 i = 0; i < pws_cnt; i++)
          {
            const u32 pw_len = device_param->pws_buf[i].pw_len;

            u8 *ptr = (u8 *) device_param->pws_buf[i].i;

            ptr[pw_len] = 0x01;
          }
        }
        else if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
        {
          for (u32 i = 0; i < pws_cnt; i++)
          {
            const u32 pw_len = device_param->pws_buf[i].pw_len;

            u8 *ptr = (u8 *) device_param->pws_buf[i].i;

            ptr[pw_len] = 0x80;
          }
        }
      }
    }
    else if (data.attack_mode == ATTACK_MODE_HYBRID2)
    {
      if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
      {
        for (u32 i = 0; i < pws_cnt; i++)
        {
          const u32 pw_len = device_param->pws_buf[i].pw_len;

          u8 *ptr = (u8 *) device_param->pws_buf[i].i;

          ptr[pw_len] = 0x01;
        }
      }
      else if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
      {
        for (u32 i = 0; i < pws_cnt; i++)
        {
          const u32 pw_len = device_param->pws_buf[i].pw_len;

          u8 *ptr = (u8 *) device_param->pws_buf[i].i;

          ptr[pw_len] = 0x80;
        }
      }
    }

    CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_pws_buf, CL_TRUE, 0, pws_cnt * sizeof (pw_t), device_param->pws_buf, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }
  else if (data.attack_kern == ATTACK_KERN_BF)
  {
    const u64 off = device_param->words_off;

    device_param->kernel_params_mp_l_buf64[3] = off;

    run_kernel_mp (KERN_RUN_MP_L, device_param, pws_cnt);
  }

  return 0;
}

static double try_run (hc_device_param_t *device_param, hashconfig_t *hashconfig, const u32 kernel_accel, const u32 kernel_loops)
{
  const u32 kernel_power_try = device_param->device_processors * device_param->kernel_threads * kernel_accel;

  device_param->kernel_params_buf32[28] = 0;
  device_param->kernel_params_buf32[29] = kernel_loops; // not a bug, both need to be set
  device_param->kernel_params_buf32[30] = kernel_loops; // because there's two variables for inner iters for slow and fast hashes

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    run_kernel (KERN_RUN_1, device_param, kernel_power_try, true, 0, hashconfig);
  }
  else
  {
    run_kernel (KERN_RUN_2, device_param, kernel_power_try, true, 0, hashconfig);
  }

  const double exec_ms_prev = get_avg_exec_time (device_param, 1);

  return exec_ms_prev;
}

static int autotune (hc_device_param_t *device_param, hashconfig_t *hashconfig)
{
  const double target_ms = TARGET_MS_PROFILE[data.workload_profile - 1];

  const u32 kernel_accel_min = device_param->kernel_accel_min;
  const u32 kernel_accel_max = device_param->kernel_accel_max;

  const u32 kernel_loops_min = device_param->kernel_loops_min;
  const u32 kernel_loops_max = device_param->kernel_loops_max;

  u32 kernel_accel = kernel_accel_min;
  u32 kernel_loops = kernel_loops_min;

  // in this case the user specified a fixed -u and -n on the commandline
  // no way to tune anything
  // but we need to run a few caching rounds

  if ((kernel_loops_min == kernel_loops_max) && (kernel_accel_min == kernel_accel_max))
  {
    if (hashconfig->hash_mode != 2000)
    {
      try_run (device_param, hashconfig, kernel_accel, kernel_loops);
      try_run (device_param, hashconfig, kernel_accel, kernel_loops);
      try_run (device_param, hashconfig, kernel_accel, kernel_loops);
      try_run (device_param, hashconfig, kernel_accel, kernel_loops);
    }

    device_param->kernel_accel = kernel_accel;
    device_param->kernel_loops = kernel_loops;

    const u32 kernel_power = device_param->device_processors * device_param->kernel_threads * device_param->kernel_accel;

    device_param->kernel_power = kernel_power;

    return 0;
  }

  // from here it's clear we are allowed to autotune
  // so let's init some fake words

  const u32 kernel_power_max = device_param->device_processors * device_param->kernel_threads * kernel_accel_max;

  if (data.attack_kern == ATTACK_KERN_BF)
  {
    run_kernel_memset (device_param, device_param->d_pws_buf, 7, kernel_power_max * sizeof (pw_t));
  }
  else
  {
    for (u32 i = 0; i < kernel_power_max; i++)
    {
      device_param->pws_buf[i].i[0]   = i;
      device_param->pws_buf[i].i[1]   = 0x01234567;
      device_param->pws_buf[i].pw_len = 7 + (i & 7);
    }

    cl_int CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_pws_buf, CL_TRUE, 0, kernel_power_max * sizeof (pw_t), device_param->pws_buf, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (data.kernel_rules_cnt > 1)
    {
      cl_int CL_err = hc_clEnqueueCopyBuffer (data.ocl, device_param->command_queue, device_param->d_rules, device_param->d_rules_c, 0, 0, MIN (kernel_loops_max, KERNEL_RULES) * sizeof (kernel_rule_t), 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }
    }
  }
  else
  {
    run_kernel_amp (device_param, kernel_power_max);
  }

  #define VERIFIER_CNT 1

  // first find out highest kernel-loops that stays below target_ms

  if (kernel_loops_min < kernel_loops_max)
  {
    for (kernel_loops = kernel_loops_max; kernel_loops > kernel_loops_min; kernel_loops >>= 1)
    {
      double exec_ms = try_run (device_param, hashconfig, kernel_accel_min, kernel_loops);

      for (int i = 0; i < VERIFIER_CNT; i++)
      {
        double exec_ms_v = try_run (device_param, hashconfig, kernel_accel_min, kernel_loops);

        exec_ms = MIN (exec_ms, exec_ms_v);
      }

      if (exec_ms < target_ms) break;
    }
  }

  // now the same for kernel-accel but with the new kernel-loops from previous loop set

  #define STEPS_CNT 10

  if (kernel_accel_min < kernel_accel_max)
  {
    for (int i = 0; i < STEPS_CNT; i++)
    {
      const u32 kernel_accel_try = 1u << i;

      if (kernel_accel_try < kernel_accel_min) continue;
      if (kernel_accel_try > kernel_accel_max) break;

      double exec_ms = try_run (device_param, hashconfig, kernel_accel_try, kernel_loops);

      for (int i = 0; i < VERIFIER_CNT; i++)
      {
        double exec_ms_v = try_run (device_param, hashconfig, kernel_accel_try, kernel_loops);

        exec_ms = MIN (exec_ms, exec_ms_v);
      }

      if (exec_ms > target_ms) break;

      kernel_accel = kernel_accel_try;
    }
  }

  // at this point we want to know the actual runtime for the following reason:
  // we need a reference for the balancing loop following up, and this
  // the balancing loop can have an effect that the creates a new opportunity, for example:
  //   if the target is 95 ms and the current runtime is 48ms the above loop
  //   stopped the execution because the previous exec_ms was > 95ms
  //   due to the rebalance it's possible that the runtime reduces from 48ms to 47ms
  //   and this creates the possibility to double the workload -> 47 * 2 = 95ms, which is < 96ms

  double exec_ms_pre_final = try_run (device_param, hashconfig, kernel_accel, kernel_loops);

  for (int i = 0; i < VERIFIER_CNT; i++)
  {
    double exec_ms_pre_final_v = try_run (device_param, hashconfig, kernel_accel, kernel_loops);

    exec_ms_pre_final = MIN (exec_ms_pre_final, exec_ms_pre_final_v);
  }

  u32 diff = kernel_loops - kernel_accel;

  if ((kernel_loops_min < kernel_loops_max) && (kernel_accel_min < kernel_accel_max))
  {
    u32 kernel_accel_orig = kernel_accel;
    u32 kernel_loops_orig = kernel_loops;

    for (u32 f = 1; f < 1024; f++)
    {
      const u32 kernel_accel_try = kernel_accel_orig * f;
      const u32 kernel_loops_try = kernel_loops_orig / f;

      if (kernel_accel_try > kernel_accel_max) break;
      if (kernel_loops_try < kernel_loops_min) break;

      u32 diff_new = kernel_loops_try - kernel_accel_try;

      if (diff_new > diff) break;

      diff_new = diff;

      double exec_ms = try_run (device_param, hashconfig, kernel_accel_try, kernel_loops_try);

      for (int i = 0; i < VERIFIER_CNT; i++)
      {
        double exec_ms_v = try_run (device_param, hashconfig, kernel_accel_try, kernel_loops_try);

        exec_ms = MIN (exec_ms, exec_ms_v);
      }

      if (exec_ms < exec_ms_pre_final)
      {
        exec_ms_pre_final = exec_ms;

        kernel_accel = kernel_accel_try;
        kernel_loops = kernel_loops_try;
      }
    }
  }

  const double exec_left = target_ms / exec_ms_pre_final;

  const double accel_left = kernel_accel_max / kernel_accel;

  const double exec_accel_min = MIN (exec_left, accel_left); // we want that to be int

  if (exec_accel_min >= 1.0)
  {
    // this is safe to not overflow kernel_accel_max because of accel_left

    kernel_accel *= (u32) exec_accel_min;
  }

  // reset them fake words

  /*
  memset (device_param->pws_buf, 0, kernel_power_max * sizeof (pw_t));

  hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_pws_buf,     CL_TRUE, 0, kernel_power_max * sizeof (pw_t), device_param->pws_buf, 0, NULL, NULL);
  hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_pws_amp_buf, CL_TRUE, 0, kernel_power_max * sizeof (pw_t), device_param->pws_buf, 0, NULL, NULL);
  */

  run_kernel_memset (device_param, device_param->d_pws_buf, 0, kernel_power_max * sizeof (pw_t));

  if (hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL)
  {
    run_kernel_memset (device_param, device_param->d_pws_amp_buf, 0, kernel_power_max * sizeof (pw_t));
  }

  // reset timer

  device_param->exec_pos = 0;

  memset (device_param->exec_ms, 0, EXEC_CACHE * sizeof (double));

  memset (device_param->exec_us_prev1, 0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev2, 0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev3, 0, EXPECTED_ITERATIONS * sizeof (double));

  // store

  device_param->kernel_accel = kernel_accel;
  device_param->kernel_loops = kernel_loops;

  const u32 kernel_power = device_param->device_processors * device_param->kernel_threads * device_param->kernel_accel;

  device_param->kernel_power = kernel_power;

  #if defined (DEBUG)

  if (data.quiet == 0)
  {
    clear_prompt ();

    log_info ("- Device #%u: autotuned kernel-accel to %u\n"
              "- Device #%u: autotuned kernel-loops to %u\n",
              device_param->device_id + 1, kernel_accel,
              device_param->device_id + 1, kernel_loops);

    fprintf (stdout, "%s", PROMPT);

    fflush (stdout);
  }

  #endif

  return 0;
}

static int run_cracker (hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint pws_cnt)
{
  char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  // init speed timer

  uint speed_pos = device_param->speed_pos;

  #if defined (_POSIX)
  if (device_param->timer_speed.tv_sec == 0)
  {
    hc_timer_set (&device_param->timer_speed);
  }
  #endif

  #if defined (_WIN)
  if (device_param->timer_speed.QuadPart == 0)
  {
    hc_timer_set (&device_param->timer_speed);
  }
  #endif

  // find higest password length, this is for optimization stuff

  uint highest_pw_len = 0;

  if (data.attack_kern == ATTACK_KERN_STRAIGHT)
  {
  }
  else if (data.attack_kern == ATTACK_KERN_COMBI)
  {
  }
  else if (data.attack_kern == ATTACK_KERN_BF)
  {
    highest_pw_len = device_param->kernel_params_mp_l_buf32[4]
                   + device_param->kernel_params_mp_l_buf32[5];
  }

  // iteration type

  uint innerloop_step = 0;
  uint innerloop_cnt  = 0;

  if      (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)   innerloop_step = device_param->kernel_loops;
  else                                                      innerloop_step = 1;

  if      (data.attack_kern == ATTACK_KERN_STRAIGHT) innerloop_cnt  = data.kernel_rules_cnt;
  else if (data.attack_kern == ATTACK_KERN_COMBI)    innerloop_cnt  = data.combs_cnt;
  else if (data.attack_kern == ATTACK_KERN_BF)       innerloop_cnt  = data.bfs_cnt;

  // loop start: most outer loop = salt iteration, then innerloops (if multi)

  for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
  {
    while (data.devices_status == STATUS_PAUSED) hc_sleep (1);

    if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

    if (data.devices_status == STATUS_CRACKED) break;
    if (data.devices_status == STATUS_ABORTED) break;
    if (data.devices_status == STATUS_QUIT)    break;
    if (data.devices_status == STATUS_BYPASS)  break;

    salt_t *salt_buf = &data.salts_buf[salt_pos];

    device_param->kernel_params_buf32[27] = salt_pos;
    device_param->kernel_params_buf32[31] = salt_buf->digests_cnt;
    device_param->kernel_params_buf32[32] = salt_buf->digests_offset;

    FILE *combs_fp = device_param->combs_fp;

    if (data.attack_mode == ATTACK_MODE_COMBI)
    {
      rewind (combs_fp);
    }

    // innerloops

    for (uint innerloop_pos = 0; innerloop_pos < innerloop_cnt; innerloop_pos += innerloop_step)
    {
      while (data.devices_status == STATUS_PAUSED) hc_sleep (1);

      if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;

      uint fast_iteration = 0;

      uint innerloop_left = innerloop_cnt - innerloop_pos;

      if (innerloop_left > innerloop_step)
      {
        innerloop_left = innerloop_step;

        fast_iteration = 1;
      }

      device_param->innerloop_pos  = innerloop_pos;
      device_param->innerloop_left = innerloop_left;

      device_param->kernel_params_buf32[30] = innerloop_left;

      // i think we can get rid of this
      if (innerloop_left == 0)
      {
        puts ("bug, how should this happen????\n");

        continue;
      }

      if (data.salts_shown[salt_pos] == 1)
      {
        data.words_progress_done[salt_pos] += (u64) pws_cnt * (u64) innerloop_left;

        continue;
      }

      // initialize amplifiers

      if (data.attack_mode == ATTACK_MODE_COMBI)
      {
        uint i = 0;

        while (i < innerloop_left)
        {
          if (feof (combs_fp)) break;

          int line_len = fgetl (combs_fp, line_buf);

          if (line_len >= PW_MAX1) continue;

          line_len = convert_from_hex (line_buf, line_len);

          char *line_buf_new = line_buf;

          if (run_rule_engine (data.rule_len_r, data.rule_buf_r))
          {
            char rule_buf_out[BLOCK_SIZE] = { 0 };

            int rule_len_out = _old_apply_rule (data.rule_buf_r, data.rule_len_r, line_buf, line_len, rule_buf_out);

            if (rule_len_out < 0)
            {
              data.words_progress_rejected[salt_pos] += pws_cnt;

              continue;
            }

            line_len = rule_len_out;

            line_buf_new = rule_buf_out;
          }

          line_len = MIN (line_len, PW_DICTMAX);

          u8 *ptr = (u8 *) device_param->combs_buf[i].i;

          memcpy (ptr, line_buf_new, line_len);

          memset (ptr + line_len, 0, PW_DICTMAX1 - line_len);

          if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
          {
            uppercase (ptr, line_len);
          }

          if (data.combs_mode == COMBINATOR_MODE_BASE_LEFT)
          {
            if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
            {
              ptr[line_len] = 0x80;
            }

            if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
            {
              ptr[line_len] = 0x01;
            }
          }

          device_param->combs_buf[i].pw_len = line_len;

          i++;
        }

        for (uint j = i; j < innerloop_left; j++)
        {
          device_param->combs_buf[j].i[0] = 0;
          device_param->combs_buf[j].i[1] = 0;
          device_param->combs_buf[j].i[2] = 0;
          device_param->combs_buf[j].i[3] = 0;
          device_param->combs_buf[j].i[4] = 0;
          device_param->combs_buf[j].i[5] = 0;
          device_param->combs_buf[j].i[6] = 0;
          device_param->combs_buf[j].i[7] = 0;

          device_param->combs_buf[j].pw_len = 0;
        }

        innerloop_left = i;
      }
      else if (data.attack_mode == ATTACK_MODE_BF)
      {
        u64 off = innerloop_pos;

        device_param->kernel_params_mp_r_buf64[3] = off;

        run_kernel_mp (KERN_RUN_MP_R, device_param, innerloop_left);
      }
      else if (data.attack_mode == ATTACK_MODE_HYBRID1)
      {
        u64 off = innerloop_pos;

        device_param->kernel_params_mp_buf64[3] = off;

        run_kernel_mp (KERN_RUN_MP, device_param, innerloop_left);
      }
      else if (data.attack_mode == ATTACK_MODE_HYBRID2)
      {
        u64 off = innerloop_pos;

        device_param->kernel_params_mp_buf64[3] = off;

        run_kernel_mp (KERN_RUN_MP, device_param, innerloop_left);
      }

      // copy amplifiers

      if (data.attack_mode == ATTACK_MODE_STRAIGHT)
      {
        cl_int CL_err = hc_clEnqueueCopyBuffer (data.ocl, device_param->command_queue, device_param->d_rules, device_param->d_rules_c, innerloop_pos * sizeof (kernel_rule_t), 0, innerloop_left * sizeof (kernel_rule_t), 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (data.attack_mode == ATTACK_MODE_COMBI)
      {
        cl_int CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_combs_c, CL_TRUE, 0, innerloop_left * sizeof (comb_t), device_param->combs_buf, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (data.attack_mode == ATTACK_MODE_BF)
      {
        cl_int CL_err = hc_clEnqueueCopyBuffer (data.ocl, device_param->command_queue, device_param->d_bfs, device_param->d_bfs_c, 0, 0, innerloop_left * sizeof (bf_t), 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (data.attack_mode == ATTACK_MODE_HYBRID1)
      {
        cl_int CL_err = hc_clEnqueueCopyBuffer (data.ocl, device_param->command_queue, device_param->d_combs, device_param->d_combs_c, 0, 0, innerloop_left * sizeof (comb_t), 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (data.attack_mode == ATTACK_MODE_HYBRID2)
      {
        cl_int CL_err = hc_clEnqueueCopyBuffer (data.ocl, device_param->command_queue, device_param->d_combs, device_param->d_combs_c, 0, 0, innerloop_left * sizeof (comb_t), 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }

      if (data.benchmark == 1)
      {
        hc_timer_set (&device_param->timer_speed);
      }

      int rc = choose_kernel (device_param, hashconfig, hashconfig->attack_exec, data.attack_mode, hashconfig->opts_type, salt_buf, highest_pw_len, pws_cnt, fast_iteration);

      if (rc == -1) return -1;

      if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;

      /**
       * result
       */

      if (data.benchmark == 0)
      {
        check_cracked (device_param, salt_pos, hashconfig);
      }

      /**
       * progress
       */

      u64 perf_sum_all = (u64) pws_cnt * (u64) innerloop_left;

      hc_thread_mutex_lock (mux_counter);

      data.words_progress_done[salt_pos] += perf_sum_all;

      hc_thread_mutex_unlock (mux_counter);

      /**
       * speed
       */

      double speed_ms;

      hc_timer_get (device_param->timer_speed, speed_ms);

      hc_timer_set (&device_param->timer_speed);

      // current speed

      //hc_thread_mutex_lock (mux_display);

      device_param->speed_cnt[speed_pos] = perf_sum_all;

      device_param->speed_ms[speed_pos] = speed_ms;

      //hc_thread_mutex_unlock (mux_display);

      speed_pos++;

      if (speed_pos == SPEED_CACHE)
      {
        speed_pos = 0;
      }

      /**
       * benchmark
       */

      if (data.benchmark == 1) break;
    }
  }

  device_param->speed_pos = speed_pos;

  myfree (line_buf);

  return 0;
}

static void *thread_monitor (void *p)
{
  uint runtime_check = 0;
  uint remove_check  = 0;
  uint status_check  = 0;
  uint restore_check = 0;

  uint restore_left = data.restore_timer;
  uint remove_left  = data.remove_timer;
  uint status_left  = data.status_timer;

  #if defined (HAVE_HWMON)
  uint hwmon_check = 0;

  int slowdown_warnings = 0;

  // these variables are mainly used for fan control

  int *fan_speed_chgd = (int *) mycalloc (data.devices_cnt, sizeof (int));

  // temperature controller "loopback" values

  int *temp_diff_old = (int *) mycalloc (data.devices_cnt, sizeof (int));
  int *temp_diff_sum = (int *) mycalloc (data.devices_cnt, sizeof (int));

  int temp_threshold = 1; // degrees celcius

  int fan_speed_min =  15; // in percentage
  int fan_speed_max = 100;

  time_t last_temp_check_time;
  #endif // HAVE_HWMON

  uint sleep_time = 1;

  if (data.runtime)
  {
    runtime_check = 1;
  }

  if (data.restore_timer)
  {
    restore_check = 1;
  }

  if ((data.remove == 1) && (data.hashlist_mode == HL_MODE_FILE))
  {
    remove_check = 1;
  }

  if (data.status == 1)
  {
    status_check = 1;
  }

  #if defined (HAVE_HWMON)
  if (data.gpu_temp_disable == 0)
  {
    time (&last_temp_check_time);

    hwmon_check = 1;
  }
  #endif

  if ((runtime_check == 0) && (remove_check == 0) && (status_check == 0) && (restore_check == 0))
  {
    #if defined (HAVE_HWMON)
    if (hwmon_check == 0)
    #endif
    return (p);
  }

  while (data.shutdown_inner == 0)
  {
    hc_sleep (sleep_time);

    if (data.devices_status != STATUS_RUNNING) continue;

    #if defined (HAVE_HWMON)

    if (hwmon_check == 1)
    {
      hc_thread_mutex_lock (mux_hwmon);

      for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &data.devices_param[device_id];

        if (device_param->skipped) continue;

        if (device_param->device_vendor_id == VENDOR_ID_NV)
        {
          if (data.hm_nvapi)
          {
            NV_GPU_PERF_POLICIES_INFO_PARAMS_V1   perfPolicies_info;
            NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 perfPolicies_status;

            memset (&perfPolicies_info,   0, sizeof (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1));
            memset (&perfPolicies_status, 0, sizeof (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1));

            perfPolicies_info.version   = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1, 1);
            perfPolicies_status.version = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1, 1);

            hm_NvAPI_GPU_GetPerfPoliciesInfo (data.hm_nvapi, data.hm_device[device_id].nvapi, &perfPolicies_info);

            perfPolicies_status.info_value = perfPolicies_info.info_value;

            hm_NvAPI_GPU_GetPerfPoliciesStatus (data.hm_nvapi, data.hm_device[device_id].nvapi, &perfPolicies_status);

            if (perfPolicies_status.throttle & 2)
            {
              if (slowdown_warnings < 3)
              {
                if (data.quiet == 0) clear_prompt ();

                log_info ("WARNING: Drivers temperature threshold hit on GPU #%d, expect performance to drop...", device_id + 1);

                if (slowdown_warnings == 2)
                {
                  log_info ("");
                }

                if (data.quiet == 0) send_prompt ();

                slowdown_warnings++;
              }
            }
            else
            {
              slowdown_warnings = 0;
            }
          }
        }
      }

      hc_thread_mutex_unlock (mux_hwmon);
    }

    if (hwmon_check == 1)
    {
      hc_thread_mutex_lock (mux_hwmon);

      time_t temp_check_time;

      time (&temp_check_time);

      uint Ta = temp_check_time - last_temp_check_time; // set Ta = sleep_time; is not good enough (see --remove etc)

      if (Ta == 0) Ta = 1;

      for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &data.devices_param[device_id];

        if (device_param->skipped) continue;

        if ((data.devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        const int temperature = hm_get_temperature_with_device_id (device_id);

        if (temperature > (int) data.gpu_temp_abort)
        {
          log_error ("ERROR: Temperature limit on GPU %d reached, aborting...", device_id + 1);

          if (data.devices_status != STATUS_QUIT) myabort ();

          break;
        }

        const int gpu_temp_retain = data.gpu_temp_retain;

        if (gpu_temp_retain)
        {
          if (data.hm_device[device_id].fan_set_supported == 1)
          {
            int temp_cur = temperature;

            int temp_diff_new = gpu_temp_retain - temp_cur;

            temp_diff_sum[device_id] = temp_diff_sum[device_id] + temp_diff_new;

            // calculate Ta value (time difference in seconds between the last check and this check)

            last_temp_check_time = temp_check_time;

            float Kp = 1.8f;
            float Ki = 0.005f;
            float Kd = 6;

            // PID controller (3-term controller: proportional - Kp, integral - Ki, derivative - Kd)

            int fan_diff_required = (int) (Kp * (float)temp_diff_new + Ki * Ta * (float)temp_diff_sum[device_id] + Kd * ((float)(temp_diff_new - temp_diff_old[device_id])) / Ta);

            if (abs (fan_diff_required) >= temp_threshold)
            {
              const int fan_speed_cur = hm_get_fanspeed_with_device_id (device_id);

              int fan_speed_level = fan_speed_cur;

              if (fan_speed_chgd[device_id] == 0) fan_speed_level = temp_cur;

              int fan_speed_new = fan_speed_level - fan_diff_required;

              if (fan_speed_new > fan_speed_max) fan_speed_new = fan_speed_max;
              if (fan_speed_new < fan_speed_min) fan_speed_new = fan_speed_min;

              if (fan_speed_new != fan_speed_cur)
              {
                int freely_change_fan_speed = (fan_speed_chgd[device_id] == 1);
                int fan_speed_must_change = (fan_speed_new > fan_speed_cur);

                if ((freely_change_fan_speed == 1) || (fan_speed_must_change == 1))
                {
                  if (device_param->device_vendor_id == VENDOR_ID_AMD)
                  {
                    hm_set_fanspeed_with_device_id_adl (device_id, fan_speed_new, 1);
                  }
                  else if (device_param->device_vendor_id == VENDOR_ID_NV)
                  {
                    #if defined (_WIN)
                    hm_set_fanspeed_with_device_id_nvapi (device_id, fan_speed_new, 1);
                    #endif

                    #if defined (__linux__)
                    hm_set_fanspeed_with_device_id_xnvctrl (device_id, fan_speed_new);
                    #endif
                  }

                  fan_speed_chgd[device_id] = 1;
                }

                temp_diff_old[device_id] = temp_diff_new;
              }
            }
          }
        }
      }

      hc_thread_mutex_unlock (mux_hwmon);
    }
    #endif // HAVE_HWMON

    if (restore_check == 1)
    {
      restore_left--;

      if (restore_left == 0)
      {
        if (data.restore_disable == 0) cycle_restore ();

        restore_left = data.restore_timer;
      }
    }

    if ((runtime_check == 1) && (data.runtime_start > 0))
    {
      double ms_paused = data.ms_paused;

      if (data.devices_status == STATUS_PAUSED)
      {
        double ms_paused_tmp = 0;

        hc_timer_get (data.timer_paused, ms_paused_tmp);

        ms_paused += ms_paused_tmp;
      }

      time_t runtime_cur;

      time (&runtime_cur);

      int runtime_left = data.proc_start + data.runtime + data.prepare_time + (ms_paused / 1000) - runtime_cur;

      if (runtime_left <= 0)
      {
        if (data.benchmark == 0)
        {
          if (data.quiet == 0) log_info ("\nNOTE: Runtime limit reached, aborting...\n");
        }

        if (data.devices_status != STATUS_QUIT) myabort ();
      }
    }

    if (remove_check == 1)
    {
      remove_left--;

      if (remove_left == 0)
      {
        if (data.digests_saved != data.digests_done)
        {
          data.digests_saved = data.digests_done;

          save_hash ();
        }

        remove_left = data.remove_timer;
      }
    }

    if (status_check == 1)
    {
      status_left--;

      if (status_left == 0)
      {
        hc_thread_mutex_lock (mux_display);

        if (data.quiet == 0) clear_prompt ();

        if (data.quiet == 0) log_info ("");

        status_display ();

        if (data.quiet == 0) log_info ("");

        hc_thread_mutex_unlock (mux_display);

        status_left = data.status_timer;
      }
    }
  }

  #if defined (HAVE_HWMON)
  myfree (fan_speed_chgd);

  myfree (temp_diff_old);
  myfree (temp_diff_sum);
  #endif

  p = NULL;

  return (p);
}

static void *thread_outfile_remove (void *p)
{
  // some hash-dependent constants

  hashconfig_t *hashconfig = data.hashconfig;

  uint dgst_size  = hashconfig->dgst_size;
  uint is_salted  = hashconfig->is_salted;
  uint esalt_size = hashconfig->esalt_size;
  uint hash_mode  = hashconfig->hash_mode;
  char separator  = hashconfig->separator;

  char *outfile_dir        = data.outfile_check_directory;
  uint outfile_check_timer = data.outfile_check_timer;

  // buffers
  hash_t hash_buf = { 0, 0, 0, 0, 0 };

  hash_buf.digest = mymalloc (dgst_size);

  if (is_salted)  hash_buf.salt =  (salt_t *) mymalloc (sizeof (salt_t));
  if (esalt_size) hash_buf.esalt = (void   *) mymalloc (esalt_size);

  uint digest_buf[64] = { 0 };

  outfile_data_t *out_info = NULL;

  char **out_files = NULL;

  time_t folder_mtime = 0;

  int  out_cnt = 0;

  uint check_left = outfile_check_timer; // or 1 if we want to check it at startup

  while (data.shutdown_inner == 0)
  {
    hc_sleep (1);

    if (data.devices_status != STATUS_RUNNING) continue;

    check_left--;

    if (check_left == 0)
    {
      struct stat outfile_check_stat;

      if (stat (outfile_dir, &outfile_check_stat) == 0)
      {
        uint is_dir = S_ISDIR (outfile_check_stat.st_mode);

        if (is_dir == 1)
        {
          if (outfile_check_stat.st_mtime > folder_mtime)
          {
            char **out_files_new = scan_directory (outfile_dir);

            int out_cnt_new = count_dictionaries (out_files_new);

            outfile_data_t *out_info_new = NULL;

            if (out_cnt_new > 0)
            {
              out_info_new = (outfile_data_t *) mycalloc (out_cnt_new, sizeof (outfile_data_t));

              for (int i = 0; i < out_cnt_new; i++)
              {
                out_info_new[i].file_name = out_files_new[i];

                // check if there are files that we have seen/checked before (and not changed)

                for (int j = 0; j < out_cnt; j++)
                {
                  if (strcmp (out_info[j].file_name, out_info_new[i].file_name) == 0)
                  {
                    struct stat outfile_stat;

                    if (stat (out_info_new[i].file_name, &outfile_stat) == 0)
                    {
                      if (outfile_stat.st_ctime == out_info[j].ctime)
                      {
                        out_info_new[i].ctime = out_info[j].ctime;
                        out_info_new[i].seek  = out_info[j].seek;
                      }
                    }
                  }
                }
              }
            }

            local_free (out_info);
            local_free (out_files);

            out_files = out_files_new;
            out_cnt   = out_cnt_new;
            out_info  = out_info_new;

            folder_mtime = outfile_check_stat.st_mtime;
          }

          for (int j = 0; j < out_cnt; j++)
          {
            FILE *fp = fopen (out_info[j].file_name, "rb");

            if (fp != NULL)
            {
              //hc_thread_mutex_lock (mux_display);

              #if defined (_POSIX)
              struct stat outfile_stat;

              fstat (fileno (fp), &outfile_stat);
              #endif

              #if defined (_WIN)
              struct stat64 outfile_stat;

              _fstat64 (fileno (fp), &outfile_stat);
              #endif

              if (outfile_stat.st_ctime > out_info[j].ctime)
              {
                out_info[j].ctime = outfile_stat.st_ctime;
                out_info[j].seek  = 0;
              }

              fseek (fp, out_info[j].seek, SEEK_SET);

              char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

              while (!feof (fp))
              {
                char *ptr = fgets (line_buf, HCBUFSIZ_LARGE - 1, fp);

                if (ptr == NULL) break;

                int line_len = strlen (line_buf);

                if (line_len <= 0) continue;

                int iter = MAX_CUT_TRIES;

                for (uint i = line_len - 1; i && iter; i--, line_len--)
                {
                  if (line_buf[i] != separator) continue;

                  int parser_status = PARSER_OK;

                  if ((hash_mode != 2500) && (hash_mode != 6800))
                  {
                    parser_status = hashconfig->parse_func (line_buf, line_len - 1, &hash_buf, hashconfig);
                  }

                  uint found = 0;

                  if (parser_status == PARSER_OK)
                  {
                    for (uint salt_pos = 0; (found == 0) && (salt_pos < data.salts_cnt); salt_pos++)
                    {
                      if (data.salts_shown[salt_pos] == 1) continue;

                      salt_t *salt_buf = &data.salts_buf[salt_pos];

                      for (uint digest_pos = 0; (found == 0) && (digest_pos < salt_buf->digests_cnt); digest_pos++)
                      {
                        uint idx = salt_buf->digests_offset + digest_pos;

                        if (data.digests_shown[idx] == 1) continue;

                        uint cracked = 0;

                        if (hash_mode == 6800)
                        {
                          if (i == salt_buf->salt_len)
                          {
                            cracked = (memcmp (line_buf, salt_buf->salt_buf, salt_buf->salt_len) == 0);
                          }
                        }
                        else if (hash_mode == 2500)
                        {
                          // BSSID : MAC1 : MAC2 (:plain)
                          if (i == (salt_buf->salt_len + 1 + 12 + 1 + 12))
                          {
                            cracked = (memcmp (line_buf, salt_buf->salt_buf, salt_buf->salt_len) == 0);

                            if (!cracked) continue;

                            // now compare MAC1 and MAC2 too, since we have this additional info
                            char *mac1_pos = line_buf + salt_buf->salt_len + 1;
                            char *mac2_pos = mac1_pos + 12 + 1;

                            wpa_t *wpas = (wpa_t *) data.esalts_buf;
                            wpa_t *wpa  = &wpas[salt_pos];

                            // compare hex string(s) vs binary MAC address(es)

                            for (uint i = 0, j = 0; i < 6; i++, j += 2)
                            {
                              if (wpa->orig_mac1[i] != hex_to_u8 ((const u8 *) &mac1_pos[j]))
                              {
                                cracked = 0;

                                break;
                              }
                            }

                            // early skip ;)
                            if (!cracked) continue;

                            for (uint i = 0, j = 0; i < 6; i++, j += 2)
                            {
                              if (wpa->orig_mac2[i] != hex_to_u8 ((const u8 *) &mac2_pos[j]))
                              {
                                cracked = 0;

                                break;
                              }
                            }
                          }
                        }
                        else
                        {
                          char *digests_buf_ptr = (char *) data.digests_buf;

                          memcpy (digest_buf, digests_buf_ptr + (data.salts_buf[salt_pos].digests_offset * dgst_size) + (digest_pos * dgst_size), dgst_size);

                          cracked = (sort_by_digest_p0p1 (digest_buf, hash_buf.digest) == 0);
                        }

                        if (cracked == 1)
                        {
                          found = 1;

                          data.digests_shown[idx] = 1;

                          data.digests_done++;

                          salt_buf->digests_done++;

                          if (salt_buf->digests_done == salt_buf->digests_cnt)
                          {
                            data.salts_shown[salt_pos] = 1;

                            data.salts_done++;

                            if (data.salts_done == data.salts_cnt) data.devices_status = STATUS_CRACKED;
                          }
                        }
                      }

                      if (data.devices_status == STATUS_CRACKED) break;
                    }
                  }

                  if (found) break;

                  if (data.devices_status == STATUS_CRACKED) break;

                  iter--;
                }

                if (data.devices_status == STATUS_CRACKED) break;
              }

              myfree (line_buf);

              out_info[j].seek = ftell (fp);

              //hc_thread_mutex_unlock (mux_display);

              fclose (fp);
            }
          }
        }
      }

      check_left = outfile_check_timer;
    }
  }

  if (esalt_size) local_free (hash_buf.esalt);

  if (is_salted)  local_free (hash_buf.salt);

  local_free (hash_buf.digest);

  local_free (out_info);

  local_free (out_files);

  p = NULL;

  return (p);
}


static void set_kernel_power_final (const u64 kernel_power_final)
{
  if (data.quiet == 0)
  {
    clear_prompt ();

    //log_info ("");

    log_info ("INFO: approaching final keyspace, workload adjusted");
    log_info ("");

    send_prompt ();
  }

  data.kernel_power_final = kernel_power_final;
}

static u32 get_power (hc_device_param_t *device_param)
{
  const u64 kernel_power_final = data.kernel_power_final;

  if (kernel_power_final)
  {
    const double device_factor = (double) device_param->hardware_power / data.hardware_power_all;

    const u64 words_left_device = (u64) CEIL (kernel_power_final * device_factor);

    // work should be at least the hardware power available without any accelerator

    const u64 work = MAX (words_left_device, device_param->hardware_power);

    return work;
  }

  return device_param->kernel_power;
}

static uint get_work (hc_device_param_t *device_param, const u64 max)
{
  hc_thread_mutex_lock (mux_dispatcher);

  const u64 words_cur  = data.words_cur;
  const u64 words_base = (data.limit == 0) ? data.words_base : MIN (data.limit, data.words_base);

  device_param->words_off = words_cur;

  const u64 kernel_power_all = data.kernel_power_all;

  const u64 words_left = words_base - words_cur;

  if (words_left < kernel_power_all)
  {
    if (data.kernel_power_final == 0)
    {
      set_kernel_power_final (words_left);
    }
  }

  const u32 kernel_power = get_power (device_param);

  uint work = MIN (words_left, kernel_power);

  work = MIN (work, max);

  data.words_cur += work;

  hc_thread_mutex_unlock (mux_dispatcher);

  return work;
}

static void SuspendThreads ()
{
  if (data.devices_status != STATUS_RUNNING) return;

  hc_timer_set (&data.timer_paused);

  data.devices_status = STATUS_PAUSED;

  log_info ("Paused");
}

static void ResumeThreads ()
{
  if (data.devices_status != STATUS_PAUSED) return;

  double ms_paused;

  hc_timer_get (data.timer_paused, ms_paused);

  data.ms_paused += ms_paused;

  data.devices_status = STATUS_RUNNING;

  log_info ("Resumed");
}

static void bypass ()
{
  data.devices_status = STATUS_BYPASS;

  log_info ("Next dictionary / mask in queue selected, bypassing current one");
}

static void stop_at_checkpoint ()
{
  if (data.devices_status != STATUS_STOP_AT_CHECKPOINT)
  {
    if (data.devices_status != STATUS_RUNNING) return;
  }

  // this feature only makes sense if --restore-disable was not specified

  if (data.restore_disable == 1)
  {
    log_info ("WARNING: This feature is disabled when --restore-disable is specified");

    return;
  }

  // check if monitoring of Restore Point updates should be enabled or disabled

  if (data.devices_status != STATUS_STOP_AT_CHECKPOINT)
  {
    data.devices_status = STATUS_STOP_AT_CHECKPOINT;

    // save the current restore point value

    data.checkpoint_cur_words = get_lowest_words_done ();

    log_info ("Checkpoint enabled: Will quit at next Restore Point update");
  }
  else
  {
    data.devices_status = STATUS_RUNNING;

    // reset the global value for checkpoint checks

    data.checkpoint_cur_words = 0;

    log_info ("Checkpoint disabled: Restore Point updates will no longer be monitored");
  }
}

static void *thread_autotune (void *p)
{
  hc_device_param_t *device_param = (hc_device_param_t *) p;

  if (device_param->skipped) return NULL;

  hashconfig_t *hashconfig = data.hashconfig;

  autotune (device_param, hashconfig);

  return NULL;
}

static void *thread_calc_stdin (void *p)
{
  hc_device_param_t *device_param = (hc_device_param_t *) p;

  if (device_param->skipped) return NULL;

  hashconfig_t *hashconfig = data.hashconfig;

  char *buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  const uint attack_kern = data.attack_kern;

  while ((data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
  {
    hc_thread_mutex_lock (mux_dispatcher);

    if (feof (stdin) != 0)
    {
      hc_thread_mutex_unlock (mux_dispatcher);

      break;
    }

    uint words_cur = 0;

    while (words_cur < device_param->kernel_power)
    {
      char *line_buf = fgets (buf, HCBUFSIZ_LARGE - 1, stdin);

      if (line_buf == NULL) break;

      uint line_len = in_superchop (line_buf);

      line_len = convert_from_hex (line_buf, line_len);

      // post-process rule engine

      if (run_rule_engine (data.rule_len_l, data.rule_buf_l))
      {
        char rule_buf_out[BLOCK_SIZE] = { 0 };

        int rule_len_out = -1;

        if (line_len < BLOCK_SIZE)
        {
          rule_len_out = _old_apply_rule (data.rule_buf_l, data.rule_len_l, line_buf, line_len, rule_buf_out);
        }

        if (rule_len_out < 0) continue;

        line_buf = rule_buf_out;
        line_len = rule_len_out;
      }

      if (line_len > PW_MAX)
      {
        continue;
      }

      // hmm that's always the case, or?

      if (attack_kern == ATTACK_KERN_STRAIGHT)
      {
        if ((line_len < data.pw_min) || (line_len > data.pw_max))
        {
          hc_thread_mutex_lock (mux_counter);

          for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
          {
            data.words_progress_rejected[salt_pos] += data.kernel_rules_cnt;
          }

          hc_thread_mutex_unlock (mux_counter);

          continue;
        }
      }

      pw_add (device_param, (u8 *) line_buf, line_len);

      words_cur++;

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;
    }

    hc_thread_mutex_unlock (mux_dispatcher);

    if (data.devices_status == STATUS_CRACKED) break;
    if (data.devices_status == STATUS_ABORTED) break;
    if (data.devices_status == STATUS_QUIT)    break;
    if (data.devices_status == STATUS_BYPASS)  break;

    // flush

    const uint pws_cnt = device_param->pws_cnt;

    if (pws_cnt)
    {
      run_copy (device_param, hashconfig, pws_cnt);

      run_cracker (device_param, hashconfig, pws_cnt);

      device_param->pws_cnt = 0;

      /*
      still required?
      if (attack_kern == ATTACK_KERN_STRAIGHT)
      {
        run_kernel_bzero (device_param, device_param->d_rules_c, device_param->size_rules_c);
      }
      else if (attack_kern == ATTACK_KERN_COMBI)
      {
        run_kernel_bzero (device_param, device_param->d_combs_c, device_param->size_combs);
      }
      */
    }
  }

  device_param->kernel_accel = 0;
  device_param->kernel_loops = 0;

  myfree (buf);

  return NULL;
}

static void *thread_calc (void *p)
{
  hc_device_param_t *device_param = (hc_device_param_t *) p;

  if (device_param->skipped) return NULL;

  hashconfig_t *hashconfig = data.hashconfig;

  const uint attack_mode = data.attack_mode;
  const uint attack_kern = data.attack_kern;

  if (attack_mode == ATTACK_MODE_BF)
  {
    while ((data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
    {
      const uint work = get_work (device_param, -1u);

      if (work == 0) break;

      const u64 words_off = device_param->words_off;
      const u64 words_fin = words_off + work;

      const uint pws_cnt = work;

      device_param->pws_cnt = pws_cnt;

      if (pws_cnt)
      {
        run_copy (device_param, hashconfig, pws_cnt);

        run_cracker (device_param, hashconfig, pws_cnt);

        device_param->pws_cnt = 0;

        /*
        still required?
        run_kernel_bzero (device_param, device_param->d_bfs_c, device_param->size_bfs);
        */
      }

      if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;

      if (data.benchmark == 1) break;

      device_param->words_done = words_fin;
    }
  }
  else
  {
    const uint segment_size = data.segment_size;

    char *dictfile = data.dictfile;

    if (attack_mode == ATTACK_MODE_COMBI)
    {
      if (data.combs_mode == COMBINATOR_MODE_BASE_RIGHT)
      {
        dictfile = data.dictfile2;
      }
    }

    FILE *fd = fopen (dictfile, "rb");

    if (fd == NULL)
    {
      log_error ("ERROR: %s: %s", dictfile, strerror (errno));

      return NULL;
    }

    if (attack_mode == ATTACK_MODE_COMBI)
    {
      const uint combs_mode = data.combs_mode;

      if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
      {
        const char *dictfilec = data.dictfile2;

        FILE *combs_fp = fopen (dictfilec, "rb");

        if (combs_fp == NULL)
        {
          log_error ("ERROR: %s: %s", dictfilec, strerror (errno));

          fclose (fd);

          return NULL;
        }

        device_param->combs_fp = combs_fp;
      }
      else if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
      {
        const char *dictfilec = data.dictfile;

        FILE *combs_fp = fopen (dictfilec, "rb");

        if (combs_fp == NULL)
        {
          log_error ("ERROR: %s: %s", dictfilec, strerror (errno));

          fclose (fd);

          return NULL;
        }

        device_param->combs_fp = combs_fp;
      }
    }

    wl_data_t *wl_data = (wl_data_t *) mymalloc (sizeof (wl_data_t));

    wl_data->buf   = (char *) mymalloc (segment_size);
    wl_data->avail = segment_size;
    wl_data->incr  = segment_size;
    wl_data->cnt   = 0;
    wl_data->pos   = 0;

    u64 words_cur = 0;

    while ((data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
    {
      u64 words_off = 0;
      u64 words_fin = 0;

      u64 max = -1llu;

      while (max)
      {
        const uint work = get_work (device_param, max);

        if (work == 0) break;

        max = 0;

        words_off = device_param->words_off;
        words_fin = words_off + work;

        char *line_buf;
        uint  line_len;

        for ( ; words_cur < words_off; words_cur++) get_next_word (wl_data, fd, &line_buf, &line_len);

        for ( ; words_cur < words_fin; words_cur++)
        {
          get_next_word (wl_data, fd, &line_buf, &line_len);

          line_len = convert_from_hex (line_buf, line_len);

          // post-process rule engine

          if (run_rule_engine (data.rule_len_l, data.rule_buf_l))
          {
            char rule_buf_out[BLOCK_SIZE] = { 0 };

            int rule_len_out = -1;

            if (line_len < BLOCK_SIZE)
            {
              rule_len_out = _old_apply_rule (data.rule_buf_l, data.rule_len_l, line_buf, line_len, rule_buf_out);
            }

            if (rule_len_out < 0) continue;

            line_buf = rule_buf_out;
            line_len = rule_len_out;
          }

          if (attack_kern == ATTACK_KERN_STRAIGHT)
          {
            if ((line_len < data.pw_min) || (line_len > data.pw_max))
            {
              max++;

              hc_thread_mutex_lock (mux_counter);

              for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
              {
                data.words_progress_rejected[salt_pos] += data.kernel_rules_cnt;
              }

              hc_thread_mutex_unlock (mux_counter);

              continue;
            }
          }
          else if (attack_kern == ATTACK_KERN_COMBI)
          {
            // do not check if minimum restriction is satisfied (line_len >= data.pw_min) here
            // since we still need to combine the plains

            if (line_len > data.pw_max)
            {
              max++;

              hc_thread_mutex_lock (mux_counter);

              for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
              {
                data.words_progress_rejected[salt_pos] += data.combs_cnt;
              }

              hc_thread_mutex_unlock (mux_counter);

              continue;
            }
          }

          pw_add (device_param, (u8 *) line_buf, line_len);

          if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

          if (data.devices_status == STATUS_CRACKED) break;
          if (data.devices_status == STATUS_ABORTED) break;
          if (data.devices_status == STATUS_QUIT)    break;
          if (data.devices_status == STATUS_BYPASS)  break;
        }

        if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

        if (data.devices_status == STATUS_CRACKED) break;
        if (data.devices_status == STATUS_ABORTED) break;
        if (data.devices_status == STATUS_QUIT)    break;
        if (data.devices_status == STATUS_BYPASS)  break;
      }

      if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;

      //
      // flush
      //

      const uint pws_cnt = device_param->pws_cnt;

      if (pws_cnt)
      {
        run_copy (device_param, hashconfig, pws_cnt);

        run_cracker (device_param, hashconfig, pws_cnt);

        device_param->pws_cnt = 0;

        /*
        still required?
        if (attack_kern == ATTACK_KERN_STRAIGHT)
        {
          run_kernel_bzero (device_param, device_param->d_rules_c, device_param->size_rules_c);
        }
        else if (attack_kern == ATTACK_KERN_COMBI)
        {
          run_kernel_bzero (device_param, device_param->d_combs_c, device_param->size_combs);
        }
        */
      }

      if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint ();

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
      if (data.devices_status == STATUS_BYPASS)  break;

      if (words_fin == 0) break;

      device_param->words_done = words_fin;
    }

    if (attack_mode == ATTACK_MODE_COMBI)
    {
      fclose (device_param->combs_fp);
    }

    free (wl_data->buf);
    free (wl_data);

    fclose (fd);
  }

  device_param->kernel_accel = 0;
  device_param->kernel_loops = 0;

  return NULL;
}

static void *thread_keypress (void *p)
{
  uint quiet = data.quiet;

  tty_break();

  while (data.shutdown_outer == 0)
  {
    int ch = tty_getchar();

    if (ch == -1) break;

    if (ch ==  0) continue;

    //https://github.com/hashcat/hashcat/issues/302
    //#if defined (_POSIX)
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_lock (mux_display);

    log_info ("");

    switch (ch)
    {
      case 's':
      case '\r':
      case '\n':

        log_info ("");

        status_display ();

        log_info ("");

        if (quiet == 0) send_prompt ();

        break;

      case 'b':

        log_info ("");

        bypass ();

        log_info ("");

        if (quiet == 0) send_prompt ();

        break;

      case 'p':

        log_info ("");

        SuspendThreads ();

        log_info ("");

        if (quiet == 0) send_prompt ();

        break;

      case 'r':

        log_info ("");

        ResumeThreads ();

        log_info ("");

        if (quiet == 0) send_prompt ();

        break;

      case 'c':

        log_info ("");

        stop_at_checkpoint ();

        log_info ("");

        if (quiet == 0) send_prompt ();

        break;

      case 'q':

        log_info ("");

        myabort ();

        break;
    }

    //https://github.com/hashcat/hashcat/issues/302
    //#if defined (_POSIX)
    //if (ch != '\n')
    //#endif

    hc_thread_mutex_unlock (mux_display);
  }

  tty_fix();

  return (p);
}

static void weak_hash_check (hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint salt_pos)
{
  if (!device_param)
  {
    log_error ("ERROR: %s : Invalid argument", __func__);

    exit (-1);
  }

  salt_t *salt_buf = &data.salts_buf[salt_pos];

  device_param->kernel_params_buf32[27] = salt_pos;
  device_param->kernel_params_buf32[30] = 1;
  device_param->kernel_params_buf32[31] = salt_buf->digests_cnt;
  device_param->kernel_params_buf32[32] = salt_buf->digests_offset;
  device_param->kernel_params_buf32[33] = 0;
  device_param->kernel_params_buf32[34] = 1;

  char *dictfile_old = data.dictfile;

  const char *weak_hash_check = "weak-hash-check";

  data.dictfile = (char *) weak_hash_check;

  uint cmd0_rule_old = data.kernel_rules_buf[0].cmds[0];

  data.kernel_rules_buf[0].cmds[0] = 0;

  /**
   * run the kernel
   */

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    run_kernel (KERN_RUN_1, device_param, 1, false, 0, hashconfig);
  }
  else
  {
    run_kernel (KERN_RUN_1, device_param, 1, false, 0, hashconfig);

    uint loop_step = 16;

    const uint iter = salt_buf->salt_iter;

    for (uint loop_pos = 0; loop_pos < iter; loop_pos += loop_step)
    {
      uint loop_left = iter - loop_pos;

      loop_left = MIN (loop_left, loop_step);

      device_param->kernel_params_buf32[28] = loop_pos;
      device_param->kernel_params_buf32[29] = loop_left;

      run_kernel (KERN_RUN_2, device_param, 1, false, 0, hashconfig);
    }

    run_kernel (KERN_RUN_3, device_param, 1, false, 0, hashconfig);
  }

  /**
   * result
   */

  check_cracked (device_param, salt_pos, hashconfig);

  /**
   * cleanup
   */

  device_param->kernel_params_buf32[27] = 0;
  device_param->kernel_params_buf32[28] = 0;
  device_param->kernel_params_buf32[29] = 0;
  device_param->kernel_params_buf32[30] = 0;
  device_param->kernel_params_buf32[31] = 0;
  device_param->kernel_params_buf32[32] = 0;
  device_param->kernel_params_buf32[33] = 0;
  device_param->kernel_params_buf32[34] = 0;

  data.dictfile = dictfile_old;

  data.kernel_rules_buf[0].cmds[0] = cmd0_rule_old;
}

int main (int argc, char **argv)
{
  #if defined (_WIN)
  SetConsoleWindowSize (132);
  #endif

  /**
   * To help users a bit
   */

  char *compute = getenv ("COMPUTE");

  if (compute)
  {
    static char display[100];

    snprintf (display, sizeof (display) - 1, "DISPLAY=%s", compute);

    putenv (display);
  }
  else
  {
    if (getenv ("DISPLAY") == NULL)
      putenv ((char *) "DISPLAY=:0");
  }

  if (getenv ("GPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "GPU_MAX_ALLOC_PERCENT=100");

  if (getenv ("CPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "CPU_MAX_ALLOC_PERCENT=100");

  if (getenv ("GPU_USE_SYNC_OBJECTS") == NULL)
    putenv ((char *) "GPU_USE_SYNC_OBJECTS=1");

  if (getenv ("CUDA_CACHE_DISABLE") == NULL)
    putenv ((char *) "CUDA_CACHE_DISABLE=1");

  if (getenv ("POCL_KERNEL_CACHE") == NULL)
    putenv ((char *) "POCL_KERNEL_CACHE=0");

  umask (077);

  /**
   * There's some buggy OpenCL runtime that do not support -I.
   * A workaround is to chdir() to the OpenCL folder,
   * then compile the kernels,
   * then chdir() back to where we came from so we need to save it first
   */

  char cwd[1024];

  if (getcwd (cwd, sizeof (cwd) - 1) == NULL)
  {
    log_error ("ERROR: getcwd(): %s", strerror (errno));

    return -1;
  }

  /**
   * Real init
   */

  memset (&data, 0, sizeof (hc_global_data_t));

  time_t proc_start;

  time (&proc_start);

  data.proc_start = proc_start;

  time_t prepare_start;

  time (&prepare_start);

  int    myargc = argc;
  char **myargv = argv;

  hc_thread_mutex_init (mux_dispatcher);
  hc_thread_mutex_init (mux_counter);
  hc_thread_mutex_init (mux_display);
  hc_thread_mutex_init (mux_hwmon);

  /**
   * commandline parameters
   */

  uint  usage                     = USAGE;
  uint  version                   = VERSION;
  uint  quiet                     = QUIET;
  uint  benchmark                 = BENCHMARK;
  uint  stdout_flag               = STDOUT_FLAG;
  uint  show                      = SHOW;
  uint  left                      = LEFT;
  uint  username                  = USERNAME;
  uint  remove                    = REMOVE;
  uint  remove_timer              = REMOVE_TIMER;
  u64   skip                      = SKIP;
  u64   limit                     = LIMIT;
  uint  keyspace                  = KEYSPACE;
  uint  potfile_disable           = POTFILE_DISABLE;
  char *potfile_path              = NULL;
  uint  debug_mode                = DEBUG_MODE;
  char *debug_file                = NULL;
  char *induction_dir             = NULL;
  char *outfile_check_dir         = NULL;
  uint  force                     = FORCE;
  uint  runtime                   = RUNTIME;
  uint  hash_mode                 = HASH_MODE;
  uint  attack_mode               = ATTACK_MODE;
  uint  markov_disable            = MARKOV_DISABLE;
  uint  markov_classic            = MARKOV_CLASSIC;
  uint  markov_threshold          = MARKOV_THRESHOLD;
  char *markov_hcstat             = NULL;
  char *outfile                   = NULL;
  uint  outfile_format            = OUTFILE_FORMAT;
  uint  outfile_autohex           = OUTFILE_AUTOHEX;
  uint  outfile_check_timer       = OUTFILE_CHECK_TIMER;
  uint  restore                   = RESTORE;
  uint  restore_timer             = RESTORE_TIMER;
  uint  restore_disable           = RESTORE_DISABLE;
  uint  status                    = STATUS;
  uint  status_timer              = STATUS_TIMER;
  uint  machine_readable          = MACHINE_READABLE;
  uint  loopback                  = LOOPBACK;
  uint  weak_hash_threshold       = WEAK_HASH_THRESHOLD;
  char *session                   = NULL;
  uint  hex_charset               = HEX_CHARSET;
  uint  hex_salt                  = HEX_SALT;
  uint  hex_wordlist              = HEX_WORDLIST;
  uint  rp_gen                    = RP_GEN;
  uint  rp_gen_func_min           = RP_GEN_FUNC_MIN;
  uint  rp_gen_func_max           = RP_GEN_FUNC_MAX;
  uint  rp_gen_seed               = RP_GEN_SEED;
  char *rule_buf_l                = (char *) RULE_BUF_L;
  char *rule_buf_r                = (char *) RULE_BUF_R;
  uint  increment                 = INCREMENT;
  uint  increment_min             = INCREMENT_MIN;
  uint  increment_max             = INCREMENT_MAX;
  char *cpu_affinity              = NULL;
  OCL_PTR *ocl                    = NULL;
  char *opencl_devices            = NULL;
  char *opencl_platforms          = NULL;
  char *opencl_device_types       = NULL;
  uint  opencl_vector_width       = OPENCL_VECTOR_WIDTH;
  char *truecrypt_keyfiles        = NULL;
  char *veracrypt_keyfiles        = NULL;
  uint  veracrypt_pim             = 0;
  uint  workload_profile          = WORKLOAD_PROFILE;
  uint  kernel_accel              = KERNEL_ACCEL;
  uint  kernel_loops              = KERNEL_LOOPS;
  uint  nvidia_spin_damp          = NVIDIA_SPIN_DAMP;
  uint  gpu_temp_disable          = GPU_TEMP_DISABLE;
  #if defined (HAVE_HWMON)
  uint  gpu_temp_abort            = GPU_TEMP_ABORT;
  uint  gpu_temp_retain           = GPU_TEMP_RETAIN;
  uint  powertune_enable          = POWERTUNE_ENABLE;
  #endif
  uint  logfile_disable           = LOGFILE_DISABLE;
  uint  segment_size              = SEGMENT_SIZE;
  uint  scrypt_tmto               = SCRYPT_TMTO;
  char  separator                 = SEPARATOR;
  uint  bitmap_min                = BITMAP_MIN;
  uint  bitmap_max                = BITMAP_MAX;
  char *custom_charset_1          = NULL;
  char *custom_charset_2          = NULL;
  char *custom_charset_3          = NULL;
  char *custom_charset_4          = NULL;

  #define IDX_HELP                      'h'
  #define IDX_VERSION                   'V'
  #define IDX_VERSION_LOWER             'v'
  #define IDX_QUIET                     0xff02
  #define IDX_SHOW                      0xff03
  #define IDX_LEFT                      0xff04
  #define IDX_REMOVE                    0xff05
  #define IDX_REMOVE_TIMER              0xff37
  #define IDX_SKIP                      's'
  #define IDX_LIMIT                     'l'
  #define IDX_KEYSPACE                  0xff35
  #define IDX_POTFILE_DISABLE           0xff06
  #define IDX_POTFILE_PATH              0xffe0
  #define IDX_DEBUG_MODE                0xff43
  #define IDX_DEBUG_FILE                0xff44
  #define IDX_INDUCTION_DIR             0xff46
  #define IDX_OUTFILE_CHECK_DIR         0xff47
  #define IDX_USERNAME                  0xff07
  #define IDX_FORCE                     0xff08
  #define IDX_RUNTIME                   0xff09
  #define IDX_BENCHMARK                 'b'
  #define IDX_STDOUT_FLAG               0xff77
  #define IDX_HASH_MODE                 'm'
  #define IDX_ATTACK_MODE               'a'
  #define IDX_RP_FILE                   'r'
  #define IDX_RP_GEN                    'g'
  #define IDX_RP_GEN_FUNC_MIN           0xff10
  #define IDX_RP_GEN_FUNC_MAX           0xff11
  #define IDX_RP_GEN_SEED               0xff34
  #define IDX_RULE_BUF_L                'j'
  #define IDX_RULE_BUF_R                'k'
  #define IDX_INCREMENT                 'i'
  #define IDX_INCREMENT_MIN             0xff12
  #define IDX_INCREMENT_MAX             0xff13
  #define IDX_OUTFILE                   'o'
  #define IDX_OUTFILE_FORMAT            0xff14
  #define IDX_OUTFILE_AUTOHEX_DISABLE   0xff39
  #define IDX_OUTFILE_CHECK_TIMER       0xff45
  #define IDX_RESTORE                   0xff15
  #define IDX_RESTORE_DISABLE           0xff27
  #define IDX_STATUS                    0xff17
  #define IDX_STATUS_TIMER              0xff18
  #define IDX_MACHINE_READABLE          0xff50
  #define IDX_LOOPBACK                  0xff38
  #define IDX_WEAK_HASH_THRESHOLD       0xff42
  #define IDX_SESSION                   0xff19
  #define IDX_HEX_CHARSET               0xff20
  #define IDX_HEX_SALT                  0xff21
  #define IDX_HEX_WORDLIST              0xff40
  #define IDX_MARKOV_DISABLE            0xff22
  #define IDX_MARKOV_CLASSIC            0xff23
  #define IDX_MARKOV_THRESHOLD          't'
  #define IDX_MARKOV_HCSTAT             0xff24
  #define IDX_CPU_AFFINITY              0xff25
  #define IDX_OPENCL_DEVICES            'd'
  #define IDX_OPENCL_PLATFORMS          0xff72
  #define IDX_OPENCL_DEVICE_TYPES       'D'
  #define IDX_OPENCL_VECTOR_WIDTH       0xff74
  #define IDX_WORKLOAD_PROFILE          'w'
  #define IDX_KERNEL_ACCEL              'n'
  #define IDX_KERNEL_LOOPS              'u'
  #define IDX_NVIDIA_SPIN_DAMP          0xff79
  #define IDX_GPU_TEMP_DISABLE          0xff29
  #define IDX_GPU_TEMP_ABORT            0xff30
  #define IDX_GPU_TEMP_RETAIN           0xff31
  #define IDX_POWERTUNE_ENABLE          0xff41
  #define IDX_LOGFILE_DISABLE           0xff51
  #define IDX_TRUECRYPT_KEYFILES        0xff52
  #define IDX_VERACRYPT_KEYFILES        0xff53
  #define IDX_VERACRYPT_PIM             0xff54
  #define IDX_SCRYPT_TMTO               0xff61
  #define IDX_SEGMENT_SIZE              'c'
  #define IDX_SEPARATOR                 'p'
  #define IDX_BITMAP_MIN                0xff70
  #define IDX_BITMAP_MAX                0xff71
  #define IDX_CUSTOM_CHARSET_1          '1'
  #define IDX_CUSTOM_CHARSET_2          '2'
  #define IDX_CUSTOM_CHARSET_3          '3'
  #define IDX_CUSTOM_CHARSET_4          '4'

  char short_options[] = "hVvm:a:r:j:k:g:o:t:d:D:n:u:c:p:s:l:1:2:3:4:ibw:";

  struct option long_options[] =
  {
    {"help",                      no_argument,       0, IDX_HELP},
    {"version",                   no_argument,       0, IDX_VERSION},
    {"quiet",                     no_argument,       0, IDX_QUIET},
    {"show",                      no_argument,       0, IDX_SHOW},
    {"left",                      no_argument,       0, IDX_LEFT},
    {"username",                  no_argument,       0, IDX_USERNAME},
    {"remove",                    no_argument,       0, IDX_REMOVE},
    {"remove-timer",              required_argument, 0, IDX_REMOVE_TIMER},
    {"skip",                      required_argument, 0, IDX_SKIP},
    {"limit",                     required_argument, 0, IDX_LIMIT},
    {"keyspace",                  no_argument,       0, IDX_KEYSPACE},
    {"potfile-disable",           no_argument,       0, IDX_POTFILE_DISABLE},
    {"potfile-path",              required_argument, 0, IDX_POTFILE_PATH},
    {"debug-mode",                required_argument, 0, IDX_DEBUG_MODE},
    {"debug-file",                required_argument, 0, IDX_DEBUG_FILE},
    {"induction-dir",             required_argument, 0, IDX_INDUCTION_DIR},
    {"outfile-check-dir",         required_argument, 0, IDX_OUTFILE_CHECK_DIR},
    {"force",                     no_argument,       0, IDX_FORCE},
    {"benchmark",                 no_argument,       0, IDX_BENCHMARK},
    {"stdout",                    no_argument,       0, IDX_STDOUT_FLAG},
    {"restore",                   no_argument,       0, IDX_RESTORE},
    {"restore-disable",           no_argument,       0, IDX_RESTORE_DISABLE},
    {"status",                    no_argument,       0, IDX_STATUS},
    {"status-timer",              required_argument, 0, IDX_STATUS_TIMER},
    {"machine-readable",          no_argument,       0, IDX_MACHINE_READABLE},
    {"loopback",                  no_argument,       0, IDX_LOOPBACK},
    {"weak-hash-threshold",       required_argument, 0, IDX_WEAK_HASH_THRESHOLD},
    {"session",                   required_argument, 0, IDX_SESSION},
    {"runtime",                   required_argument, 0, IDX_RUNTIME},
    {"generate-rules",            required_argument, 0, IDX_RP_GEN},
    {"generate-rules-func-min",   required_argument, 0, IDX_RP_GEN_FUNC_MIN},
    {"generate-rules-func-max",   required_argument, 0, IDX_RP_GEN_FUNC_MAX},
    {"generate-rules-seed",       required_argument, 0, IDX_RP_GEN_SEED},
    {"rule-left",                 required_argument, 0, IDX_RULE_BUF_L},
    {"rule-right",                required_argument, 0, IDX_RULE_BUF_R},
    {"hash-type",                 required_argument, 0, IDX_HASH_MODE},
    {"attack-mode",               required_argument, 0, IDX_ATTACK_MODE},
    {"rules-file",                required_argument, 0, IDX_RP_FILE},
    {"outfile",                   required_argument, 0, IDX_OUTFILE},
    {"outfile-format",            required_argument, 0, IDX_OUTFILE_FORMAT},
    {"outfile-autohex-disable",   no_argument,       0, IDX_OUTFILE_AUTOHEX_DISABLE},
    {"outfile-check-timer",       required_argument, 0, IDX_OUTFILE_CHECK_TIMER},
    {"hex-charset",               no_argument,       0, IDX_HEX_CHARSET},
    {"hex-salt",                  no_argument,       0, IDX_HEX_SALT},
    {"hex-wordlist",              no_argument,       0, IDX_HEX_WORDLIST},
    {"markov-disable",            no_argument,       0, IDX_MARKOV_DISABLE},
    {"markov-classic",            no_argument,       0, IDX_MARKOV_CLASSIC},
    {"markov-threshold",          required_argument, 0, IDX_MARKOV_THRESHOLD},
    {"markov-hcstat",             required_argument, 0, IDX_MARKOV_HCSTAT},
    {"cpu-affinity",              required_argument, 0, IDX_CPU_AFFINITY},
    {"opencl-devices",            required_argument, 0, IDX_OPENCL_DEVICES},
    {"opencl-platforms",          required_argument, 0, IDX_OPENCL_PLATFORMS},
    {"opencl-device-types",       required_argument, 0, IDX_OPENCL_DEVICE_TYPES},
    {"opencl-vector-width",       required_argument, 0, IDX_OPENCL_VECTOR_WIDTH},
    {"workload-profile",          required_argument, 0, IDX_WORKLOAD_PROFILE},
    {"kernel-accel",              required_argument, 0, IDX_KERNEL_ACCEL},
    {"kernel-loops",              required_argument, 0, IDX_KERNEL_LOOPS},
    {"nvidia-spin-damp",          required_argument, 0, IDX_NVIDIA_SPIN_DAMP},
    {"gpu-temp-disable",          no_argument,       0, IDX_GPU_TEMP_DISABLE},
    #if defined (HAVE_HWMON)
    {"gpu-temp-abort",            required_argument, 0, IDX_GPU_TEMP_ABORT},
    {"gpu-temp-retain",           required_argument, 0, IDX_GPU_TEMP_RETAIN},
    {"powertune-enable",          no_argument,       0, IDX_POWERTUNE_ENABLE},
    #endif // HAVE_HWMON
    {"logfile-disable",           no_argument,       0, IDX_LOGFILE_DISABLE},
    {"truecrypt-keyfiles",        required_argument, 0, IDX_TRUECRYPT_KEYFILES},
    {"veracrypt-keyfiles",        required_argument, 0, IDX_VERACRYPT_KEYFILES},
    {"veracrypt-pim",             required_argument, 0, IDX_VERACRYPT_PIM},
    {"segment-size",              required_argument, 0, IDX_SEGMENT_SIZE},
    {"scrypt-tmto",               required_argument, 0, IDX_SCRYPT_TMTO},
    {"seperator",                 required_argument, 0, IDX_SEPARATOR},
    {"separator",                 required_argument, 0, IDX_SEPARATOR},
    {"bitmap-min",                required_argument, 0, IDX_BITMAP_MIN},
    {"bitmap-max",                required_argument, 0, IDX_BITMAP_MAX},
    {"increment",                 no_argument,       0, IDX_INCREMENT},
    {"increment-min",             required_argument, 0, IDX_INCREMENT_MIN},
    {"increment-max",             required_argument, 0, IDX_INCREMENT_MAX},
    {"custom-charset1",           required_argument, 0, IDX_CUSTOM_CHARSET_1},
    {"custom-charset2",           required_argument, 0, IDX_CUSTOM_CHARSET_2},
    {"custom-charset3",           required_argument, 0, IDX_CUSTOM_CHARSET_3},
    {"custom-charset4",           required_argument, 0, IDX_CUSTOM_CHARSET_4},
    {0, 0, 0, 0}
  };

  uint rp_files_cnt = 0;

  char **rp_files = (char **) mycalloc (argc, sizeof (char *));

  int option_index = 0;
  int c = -1;

  optind = 1;
  optopt = 0;

  while (((c = getopt_long (argc, argv, short_options, long_options, &option_index)) != -1) && optopt == 0)
  {
    switch (c)
    {
      case IDX_HELP:          usage   = 1;      break;
      case IDX_VERSION:
      case IDX_VERSION_LOWER: version = 1;      break;
      case IDX_RESTORE:       restore = 1;      break;
      case IDX_SESSION:       session = optarg; break;
      case IDX_SHOW:          show    = 1;      break;
      case IDX_LEFT:          left    = 1;      break;
      case '?':               return -1;
    }
  }

  if (optopt != 0)
  {
    log_error ("ERROR: Invalid argument specified");

    return -1;
  }

  /**
   * exit functions
   */

  if (version)
  {
    log_info ("%s", VERSION_TAG);

    return 0;
  }

  if (usage)
  {
    usage_big_print (PROGNAME);

    return 0;
  }

  /**
   * session needs to be set, always!
   */

  if (session == NULL) session = (char *) PROGNAME;

  /**
   * folders, as discussed on https://github.com/hashcat/hashcat/issues/20
   */

  char *exec_path = get_exec_path ();


  #if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)

  char *resolved_install_folder = realpath (INSTALL_FOLDER, NULL);
  char *resolved_exec_path      = realpath (exec_path, NULL);

  if (resolved_install_folder == NULL)
  {
    log_error ("ERROR: %s: %s", resolved_install_folder, strerror (errno));

    return -1;
  }

  if (resolved_exec_path == NULL)
  {
    log_error ("ERROR: %s: %s", resolved_exec_path, strerror (errno));

    return -1;
  }

  char *install_dir = get_install_dir (resolved_exec_path);
  char *profile_dir = NULL;
  char *session_dir = NULL;
  char *shared_dir  = NULL;

  if (strcmp (install_dir, resolved_install_folder) == 0)
  {
    struct passwd *pw = getpwuid (getuid ());

    const char *homedir = pw->pw_dir;

    profile_dir = get_profile_dir (homedir);
    session_dir = get_session_dir (profile_dir);
    shared_dir  = mystrdup (SHARED_FOLDER);

    mkdir (profile_dir, 0700);
    mkdir (session_dir, 0700);
  }
  else
  {
    profile_dir = install_dir;
    session_dir = install_dir;
    shared_dir  = install_dir;
  }

  myfree (resolved_install_folder);
  myfree (resolved_exec_path);

  #else

  char *install_dir = get_install_dir (exec_path);
  char *profile_dir = install_dir;
  char *session_dir = install_dir;
  char *shared_dir  = install_dir;

  #endif

  data.install_dir = install_dir;
  data.profile_dir = profile_dir;
  data.session_dir = session_dir;
  data.shared_dir  = shared_dir;

  myfree (exec_path);

  /**
   * There's alot of problem related to bad support -I parameters when building the kernel.
   * Each OpenCL runtime handles it slightly different.
   * The most problematic is with new AMD drivers on Windows, which can not handle quote characters!
   * The best workaround found so far is to modify the TMP variable (only inside hashcat process) before the runtime is load
   */

  char cpath[1024] = { 0 };

  #if defined (_WIN)

  snprintf (cpath, sizeof (cpath) - 1, "%s\\OpenCL\\", shared_dir);

  char *cpath_real = mymalloc (MAX_PATH);

  if (GetFullPathName (cpath, MAX_PATH, cpath_real, NULL) == 0)
  {
    log_error ("ERROR: %s: %s", cpath, "GetFullPathName()");

    return -1;
  }

  #else

  snprintf (cpath, sizeof (cpath) - 1, "%s/OpenCL/", shared_dir);

  char *cpath_real = mymalloc (PATH_MAX);

  if (realpath (cpath, cpath_real) == NULL)
  {
    log_error ("ERROR: %s: %s", cpath, strerror (errno));

    return -1;
  }

  #endif

  //if (getenv ("TMP") == NULL)
  if (1)
  {
    char tmp[1000];

    snprintf (tmp, sizeof (tmp) - 1, "TMP=%s", cpath_real);

    putenv (tmp);
  }

  #if defined (_WIN)

  naive_replace (cpath_real, '\\', '/');

  // not escaping here, windows using quotes later
  // naive_escape (cpath_real, PATH_MAX,  ' ', '\\');

  #else

  naive_escape (cpath_real, PATH_MAX,  ' ', '\\');

  #endif

  /**
   * kernel cache, we need to make sure folder exist
   */

  int kernels_folder_size = strlen (profile_dir) + 1 + 7 + 1 + 1;

  char *kernels_folder = (char *) mymalloc (kernels_folder_size);

  snprintf (kernels_folder, kernels_folder_size - 1, "%s/kernels", profile_dir);

  mkdir (kernels_folder, 0700);

  myfree (kernels_folder);

  /**
   * session
   */

  size_t session_size = strlen (session_dir) + 1 + strlen (session) + 32;

  data.session = session;

  char *eff_restore_file = (char *) mymalloc (session_size);
  char *new_restore_file = (char *) mymalloc (session_size);

  snprintf (eff_restore_file, session_size - 1, "%s/%s.restore",     data.session_dir, session);
  snprintf (new_restore_file, session_size - 1, "%s/%s.restore.new", data.session_dir, session);

  data.eff_restore_file = eff_restore_file;
  data.new_restore_file = new_restore_file;

  if (((show == 1) || (left == 1)) && (restore == 1))
  {
    if (show == 1) log_error ("ERROR: Mixing --restore parameter and --show is not supported");
    else           log_error ("ERROR: Mixing --restore parameter and --left is not supported");

    return -1;
  }

  // this allows the user to use --show and --left while cracking (i.e. while another instance of hashcat is running)
  if ((show == 1) || (left == 1))
  {
    restore_disable = 1;

    restore = 0;
  }

  data.restore_disable = restore_disable;

  restore_data_t *rd = init_restore (argc, argv);

  data.rd = rd;

  /**
   * restore file
   */

  if (restore == 1)
  {
    read_restore (eff_restore_file, rd);

    if (rd->version < RESTORE_VERSION_MIN)
    {
      log_error ("ERROR: Incompatible restore-file version");

      return -1;
    }

    myargc = rd->argc;
    myargv = rd->argv;

    #if defined (_POSIX)
    rd->pid = getpid ();
    #elif defined (_WIN)
    rd->pid = GetCurrentProcessId ();
    #endif
  }

  uint hash_mode_chgd           = 0;
  uint runtime_chgd             = 0;
  uint kernel_loops_chgd        = 0;
  uint kernel_accel_chgd        = 0;
  uint nvidia_spin_damp_chgd    = 0;
  uint attack_mode_chgd         = 0;
  uint outfile_format_chgd      = 0;
  uint rp_gen_seed_chgd         = 0;
  uint remove_timer_chgd        = 0;
  uint increment_min_chgd       = 0;
  uint increment_max_chgd       = 0;
  uint workload_profile_chgd    = 0;
  uint opencl_vector_width_chgd = 0;

  optind = 1;
  optopt = 0;
  option_index = 0;

  while (((c = getopt_long (myargc, myargv, short_options, long_options, &option_index)) != -1) && optopt == 0)
  {
    switch (c)
    {
    //case IDX_HELP:                      usage                     = 1;              break;
    //case IDX_VERSION:                   version                   = 1;              break;
    //case IDX_RESTORE:                   restore                   = 1;              break;
      case IDX_QUIET:                     quiet                     = 1;              break;
    //case IDX_SHOW:                      show                      = 1;              break;
      case IDX_SHOW:                                                                  break;
    //case IDX_LEFT:                      left                      = 1;              break;
      case IDX_LEFT:                                                                  break;
      case IDX_USERNAME:                  username                  = 1;              break;
      case IDX_REMOVE:                    remove                    = 1;              break;
      case IDX_REMOVE_TIMER:              remove_timer              = atoi (optarg);
                                          remove_timer_chgd         = 1;              break;
      case IDX_POTFILE_DISABLE:           potfile_disable           = 1;              break;
      case IDX_POTFILE_PATH:              potfile_path              = optarg;         break;
      case IDX_DEBUG_MODE:                debug_mode                = atoi (optarg);  break;
      case IDX_DEBUG_FILE:                debug_file                = optarg;         break;
      case IDX_INDUCTION_DIR:             induction_dir             = optarg;         break;
      case IDX_OUTFILE_CHECK_DIR:         outfile_check_dir         = optarg;         break;
      case IDX_FORCE:                     force                     = 1;              break;
      case IDX_SKIP:                      skip                      = atoll (optarg); break;
      case IDX_LIMIT:                     limit                     = atoll (optarg); break;
      case IDX_KEYSPACE:                  keyspace                  = 1;              break;
      case IDX_BENCHMARK:                 benchmark                 = 1;              break;
      case IDX_STDOUT_FLAG:               stdout_flag               = 1;              break;
      case IDX_RESTORE:                                                               break;
      case IDX_RESTORE_DISABLE:           restore_disable           = 1;              break;
      case IDX_STATUS:                    status                    = 1;              break;
      case IDX_STATUS_TIMER:              status_timer              = atoi (optarg);  break;
      case IDX_MACHINE_READABLE:          machine_readable          = 1;              break;
      case IDX_LOOPBACK:                  loopback                  = 1;              break;
      case IDX_WEAK_HASH_THRESHOLD:       weak_hash_threshold       = atoi (optarg);  break;
    //case IDX_SESSION:                   session                   = optarg;         break;
      case IDX_SESSION:                                                               break;
      case IDX_HASH_MODE:                 hash_mode                 = atoi (optarg);
                                          hash_mode_chgd            = 1;              break;
      case IDX_RUNTIME:                   runtime                   = atoi (optarg);
                                          runtime_chgd              = 1;              break;
      case IDX_ATTACK_MODE:               attack_mode               = atoi (optarg);
                                          attack_mode_chgd          = 1;              break;
      case IDX_RP_FILE:                   rp_files[rp_files_cnt++]  = optarg;         break;
      case IDX_RP_GEN:                    rp_gen                    = atoi (optarg);  break;
      case IDX_RP_GEN_FUNC_MIN:           rp_gen_func_min           = atoi (optarg);  break;
      case IDX_RP_GEN_FUNC_MAX:           rp_gen_func_max           = atoi (optarg);  break;
      case IDX_RP_GEN_SEED:               rp_gen_seed               = atoi (optarg);
                                          rp_gen_seed_chgd          = 1;              break;
      case IDX_RULE_BUF_L:                rule_buf_l                = optarg;         break;
      case IDX_RULE_BUF_R:                rule_buf_r                = optarg;         break;
      case IDX_MARKOV_DISABLE:            markov_disable            = 1;              break;
      case IDX_MARKOV_CLASSIC:            markov_classic            = 1;              break;
      case IDX_MARKOV_THRESHOLD:          markov_threshold          = atoi (optarg);  break;
      case IDX_MARKOV_HCSTAT:             markov_hcstat             = optarg;         break;
      case IDX_OUTFILE:                   outfile                   = optarg;         break;
      case IDX_OUTFILE_FORMAT:            outfile_format            = atoi (optarg);
                                          outfile_format_chgd       = 1;              break;
      case IDX_OUTFILE_AUTOHEX_DISABLE:   outfile_autohex           = 0;              break;
      case IDX_OUTFILE_CHECK_TIMER:       outfile_check_timer       = atoi (optarg);  break;
      case IDX_HEX_CHARSET:               hex_charset               = 1;              break;
      case IDX_HEX_SALT:                  hex_salt                  = 1;              break;
      case IDX_HEX_WORDLIST:              hex_wordlist              = 1;              break;
      case IDX_CPU_AFFINITY:              cpu_affinity              = optarg;         break;
      case IDX_OPENCL_DEVICES:            opencl_devices            = optarg;         break;
      case IDX_OPENCL_PLATFORMS:          opencl_platforms          = optarg;         break;
      case IDX_OPENCL_DEVICE_TYPES:       opencl_device_types       = optarg;         break;
      case IDX_OPENCL_VECTOR_WIDTH:       opencl_vector_width       = atoi (optarg);
                                          opencl_vector_width_chgd  = 1;              break;
      case IDX_WORKLOAD_PROFILE:          workload_profile          = atoi (optarg);
                                          workload_profile_chgd     = 1;              break;
      case IDX_KERNEL_ACCEL:              kernel_accel              = atoi (optarg);
                                          kernel_accel_chgd         = 1;              break;
      case IDX_KERNEL_LOOPS:              kernel_loops              = atoi (optarg);
                                          kernel_loops_chgd         = 1;              break;
      case IDX_NVIDIA_SPIN_DAMP:          nvidia_spin_damp          = atoi (optarg);
                                          nvidia_spin_damp_chgd     = 1;              break;
      case IDX_GPU_TEMP_DISABLE:          gpu_temp_disable          = 1;              break;
      #if defined (HAVE_HWMON)
      case IDX_GPU_TEMP_ABORT:            gpu_temp_abort            = atoi (optarg);  break;
      case IDX_GPU_TEMP_RETAIN:           gpu_temp_retain           = atoi (optarg);  break;
      case IDX_POWERTUNE_ENABLE:          powertune_enable          = 1;              break;
      #endif // HAVE_HWMON
      case IDX_LOGFILE_DISABLE:           logfile_disable           = 1;              break;
      case IDX_TRUECRYPT_KEYFILES:        truecrypt_keyfiles        = optarg;         break;
      case IDX_VERACRYPT_KEYFILES:        veracrypt_keyfiles        = optarg;         break;
      case IDX_VERACRYPT_PIM:             veracrypt_pim             = atoi (optarg);  break;
      case IDX_SEGMENT_SIZE:              segment_size              = atoi (optarg);  break;
      case IDX_SCRYPT_TMTO:               scrypt_tmto               = atoi (optarg);  break;
      case IDX_SEPARATOR:                 separator                 = optarg[0];      break;
      case IDX_BITMAP_MIN:                bitmap_min                = atoi (optarg);  break;
      case IDX_BITMAP_MAX:                bitmap_max                = atoi (optarg);  break;
      case IDX_INCREMENT:                 increment                 = 1;              break;
      case IDX_INCREMENT_MIN:             increment_min             = atoi (optarg);
                                          increment_min_chgd        = 1;              break;
      case IDX_INCREMENT_MAX:             increment_max             = atoi (optarg);
                                          increment_max_chgd        = 1;              break;
      case IDX_CUSTOM_CHARSET_1:          custom_charset_1          = optarg;         break;
      case IDX_CUSTOM_CHARSET_2:          custom_charset_2          = optarg;         break;
      case IDX_CUSTOM_CHARSET_3:          custom_charset_3          = optarg;         break;
      case IDX_CUSTOM_CHARSET_4:          custom_charset_4          = optarg;         break;

      default:
        log_error ("ERROR: Invalid argument specified");
        return -1;
    }
  }

  if (optopt != 0)
  {
    log_error ("ERROR: Invalid argument specified");

    return -1;
  }

  /**
   * Inform user things getting started,
   * - this is giving us a visual header before preparations start, so we do not need to clear them afterwards
   * - we do not need to check algorithm_pos
   */

  if (quiet == 0)
  {
    if (benchmark == 1)
    {
      if (machine_readable == 0)
      {
        log_info ("%s (%s) starting in benchmark-mode...", PROGNAME, VERSION_TAG);
        log_info ("");
      }
      else
      {
        log_info ("# %s (%s) %s", PROGNAME, VERSION_TAG, ctime (&proc_start));
      }
    }
    else if (restore == 1)
    {
      log_info ("%s (%s) starting in restore-mode...", PROGNAME, VERSION_TAG);
      log_info ("");
    }
    else if (stdout_flag == 1)
    {
      // do nothing
    }
    else if (keyspace == 1)
    {
      // do nothing
    }
    else
    {
      if ((show == 1) || (left == 1))
      {
        // do nothing
      }
      else
      {
        log_info ("%s (%s) starting...", PROGNAME, VERSION_TAG);
        log_info ("");
      }
    }
  }

  /**
   * sanity check
   */

  if (attack_mode > 7)
  {
    log_error ("ERROR: Invalid attack-mode specified");

    return -1;
  }

  if (runtime_chgd && runtime == 0) // just added to remove compiler warnings for runtime_chgd
  {
    log_error ("ERROR: Invalid runtime specified");

    return -1;
  }

  if (hash_mode_chgd && hash_mode > 14100) // just added to remove compiler warnings for hash_mode_chgd
  {
    log_error ("ERROR: Invalid hash-type specified");

    return -1;
  }

  // renamed hash modes

  if (hash_mode_chgd)
  {
    int n = -1;

    switch (hash_mode)
    {
      case 123: n = 124;
                break;
    }

    if (n >= 0)
    {
      log_error ("Old -m specified, use -m %d instead", n);

      return -1;
    }
  }

  if (username == 1)
  {
    if ((hash_mode == 2500) || (hash_mode == 5200) || ((hash_mode >= 6200) && (hash_mode <= 6299)) || ((hash_mode >= 13700) && (hash_mode <= 13799)))
    {
      log_error ("ERROR: Mixing support for user names and hashes of type %s is not supported", strhashtype (hash_mode));

      return -1;
    }
  }

  if (outfile_format > 16)
  {
    log_error ("ERROR: Invalid outfile-format specified");

    return -1;
  }

  if (left == 1)
  {
    if (outfile_format_chgd == 1)
    {
      if (outfile_format > 1)
      {
        log_error ("ERROR: Mixing outfile-format > 1 with left parameter is not allowed");

        return -1;
      }
    }
    else
    {
      outfile_format = OUTFILE_FMT_HASH;
    }
  }

  if (show == 1)
  {
    if (outfile_format_chgd == 1)
    {
      if ((outfile_format > 7) && (outfile_format < 16))
      {
        log_error ("ERROR: Mixing outfile-format > 7 with show parameter is not allowed");

        return -1;
      }
    }
  }

  if (increment_min < INCREMENT_MIN)
  {
    log_error ("ERROR: Invalid increment-min specified");

    return -1;
  }

  if (increment_max > INCREMENT_MAX)
  {
    log_error ("ERROR: Invalid increment-max specified");

    return -1;
  }

  if (increment_min > increment_max)
  {
    log_error ("ERROR: Invalid increment-min specified");

    return -1;
  }

  if ((increment == 1) && (attack_mode == ATTACK_MODE_STRAIGHT))
  {
    log_error ("ERROR: Increment is not allowed in attack-mode 0");

    return -1;
  }

  if ((increment == 0) && (increment_min_chgd == 1))
  {
    log_error ("ERROR: Increment-min is only supported combined with increment switch");

    return -1;
  }

  if ((increment == 0) && (increment_max_chgd == 1))
  {
    log_error ("ERROR: Increment-max is only supported combined with increment switch");

    return -1;
  }

  if (rp_files_cnt && rp_gen)
  {
    log_error ("ERROR: Use of both rules-file and rules-generate is not supported");

    return -1;
  }

  if (rp_files_cnt || rp_gen)
  {
    if (attack_mode != ATTACK_MODE_STRAIGHT)
    {
      log_error ("ERROR: Use of rules-file or rules-generate only allowed in attack-mode 0");

      return -1;
    }
  }

  if (rp_gen_func_min > rp_gen_func_max)
  {
    log_error ("ERROR: Invalid rp-gen-func-min specified");

    return -1;
  }

  if (kernel_accel_chgd == 1)
  {
    if (force == 0)
    {
      log_info ("The manual use of the -n option (or --kernel-accel) is outdated");
      log_info ("Please consider using the -w option instead");
      log_info ("You can use --force to override this but do not post error reports if you do so");
      log_info ("");

      return -1;
    }

    if (kernel_accel < 1)
    {
      log_error ("ERROR: Invalid kernel-accel specified");

      return -1;
    }

    if (kernel_accel > 1024)
    {
      log_error ("ERROR: Invalid kernel-accel specified");

      return -1;
    }
  }

  if (kernel_loops_chgd == 1)
  {
    if (force == 0)
    {
      log_info ("The manual use of the -u option (or --kernel-loops) is outdated");
      log_info ("Please consider using the -w option instead");
      log_info ("You can use --force to override this but do not post error reports if you do so");
      log_info ("");

      return -1;
    }

    if (kernel_loops < 1)
    {
      log_error ("ERROR: Invalid kernel-loops specified");

      return -1;
    }

    if (kernel_loops > 1024)
    {
      log_error ("ERROR: Invalid kernel-loops specified");

      return -1;
    }
  }

  if ((workload_profile < 1) || (workload_profile > 4))
  {
    log_error ("ERROR: workload-profile %i not available", workload_profile);

    return -1;
  }

  if (opencl_vector_width_chgd && (!is_power_of_2(opencl_vector_width) || opencl_vector_width > 16))
  {
    log_error ("ERROR: opencl-vector-width %i not allowed", opencl_vector_width);

    return -1;
  }

  if (show == 1 || left == 1)
  {
    attack_mode = ATTACK_MODE_NONE;

    if (remove == 1)
    {
      log_error ("ERROR: Mixing remove parameter not allowed with show parameter or left parameter");

      return -1;
    }

    if (potfile_disable == 1)
    {
      log_error ("ERROR: Mixing potfile-disable parameter not allowed with show parameter or left parameter");

      return -1;
    }
  }

  if (show == 1)
  {
    if (outfile_autohex == 0)
    {
      log_error ("ERROR: Mixing outfile-autohex-disable parameter not allowed with show parameter");

      return -1;
    }
  }

  uint attack_kern = ATTACK_KERN_NONE;

  switch (attack_mode)
  {
    case ATTACK_MODE_STRAIGHT: attack_kern = ATTACK_KERN_STRAIGHT; break;
    case ATTACK_MODE_COMBI:    attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_BF:       attack_kern = ATTACK_KERN_BF;       break;
    case ATTACK_MODE_HYBRID1:  attack_kern = ATTACK_KERN_COMBI;    break;
    case ATTACK_MODE_HYBRID2:  attack_kern = ATTACK_KERN_COMBI;    break;
  }

  if (benchmark == 1)
  {
    if (myargv[optind] != 0)
    {
      log_error ("ERROR: Invalid argument for benchmark mode specified");

      return -1;
    }

    if (attack_mode_chgd == 1)
    {
      if (attack_mode != ATTACK_MODE_BF)
      {
        log_error ("ERROR: Only attack-mode 3 allowed in benchmark mode");

        return -1;
      }
    }
  }
  else
  {
    if (stdout_flag == 1) // no hash here
    {
      optind--;
    }

    if (keyspace == 1)
    {
      int num_additional_params = 1;

      if (attack_kern == ATTACK_KERN_COMBI)
      {
        num_additional_params = 2;
      }

      int keyspace_wordlist_specified = myargc - optind - num_additional_params;

      if (keyspace_wordlist_specified == 0) optind--;
    }

    if (attack_kern == ATTACK_KERN_NONE)
    {
      if ((optind + 1) != myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else if (attack_kern == ATTACK_KERN_STRAIGHT)
    {
      if ((optind + 1) > myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else if (attack_kern == ATTACK_KERN_COMBI)
    {
      if ((optind + 3) != myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else if (attack_kern == ATTACK_KERN_BF)
    {
      if ((optind + 1) > myargc)
      {
        usage_mini_print (myargv[0]);

        return -1;
      }
    }
    else
    {
      usage_mini_print (myargv[0]);

      return -1;
    }
  }

  if (skip != 0 && limit != 0)
  {
    limit += skip;
  }

  if (keyspace == 1)
  {
    if (show == 1)
    {
      log_error ("ERROR: Combining show parameter with keyspace parameter is not allowed");

      return -1;
    }
    else if (left == 1)
    {
      log_error ("ERROR: Combining left parameter with keyspace parameter is not allowed");

      return -1;
    }

    potfile_disable = 1;

    restore_disable = 1;

    restore = 0;

    weak_hash_threshold = 0;

    quiet = 1;
  }

  if (stdout_flag == 1)
  {
    status_timer          = 0;
    restore_timer         = 0;
    restore_disable       = 1;
    restore               = 0;
    potfile_disable       = 1;
    weak_hash_threshold   = 0;
    gpu_temp_disable      = 1;
    hash_mode             = 2000;
    quiet                 = 1;
    outfile_format        = OUTFILE_FMT_PLAIN;
    kernel_accel          = 1024;
    kernel_loops          = 1024;
    force                 = 1;
    outfile_check_timer   = 0;
    session               = "stdout";
    opencl_vector_width   = 1;
  }

  if (remove_timer_chgd == 1)
  {
    if (remove == 0)
    {
      log_error ("ERROR: Parameter remove-timer require parameter remove enabled");

      return -1;
    }

    if (remove_timer < 1)
    {
      log_error ("ERROR: Parameter remove-timer must have a value greater than or equal to 1");

      return -1;
    }
  }

  if (loopback == 1)
  {
    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if ((rp_files_cnt == 0) && (rp_gen == 0))
      {
        log_error ("ERROR: Parameter loopback not allowed without rules-file or rules-generate");

        return -1;
      }
    }
    else
    {
      log_error ("ERROR: Parameter loopback allowed in attack-mode 0 only");

      return -1;
    }
  }

  if (debug_mode > 0)
  {
    if (attack_mode != ATTACK_MODE_STRAIGHT)
    {
      log_error ("ERROR: Parameter debug-mode option is only available with attack-mode 0");

      return -1;
    }

    if ((rp_files_cnt == 0) && (rp_gen == 0))
    {
      log_error ("ERROR: Parameter debug-mode not allowed without rules-file or rules-generate");

      return -1;
    }
  }

  if (debug_mode > 4)
  {
    log_error ("ERROR: Invalid debug-mode specified");

    return -1;
  }

  if (debug_file != NULL)
  {
    if (debug_mode < 1)
    {
      log_error ("ERROR: Parameter debug-file requires parameter debug-mode to be set");

      return -1;
    }
  }

  if (induction_dir != NULL)
  {
    if (attack_mode == ATTACK_MODE_BF)
    {
      log_error ("ERROR: Parameter induction-dir not allowed with brute-force attacks");

      return -1;
    }
  }

  if (attack_mode != ATTACK_MODE_STRAIGHT)
  {
    if ((weak_hash_threshold != WEAK_HASH_THRESHOLD) && (weak_hash_threshold != 0))
    {
      log_error ("ERROR: setting --weak-hash-threshold allowed only in straight-attack mode");

      return -1;
    }

    weak_hash_threshold = 0;
  }

  if (nvidia_spin_damp > 100)
  {
    log_error ("ERROR: setting --nvidia-spin-damp must be between 0 and 100 (inclusive)");

    return -1;
  }


  /**
   * induction directory
   */

  char *induction_directory = NULL;

  if (attack_mode != ATTACK_MODE_BF)
  {
    if (induction_dir == NULL)
    {
      induction_directory = (char *) mymalloc (session_size);

      snprintf (induction_directory, session_size - 1, "%s/%s.%s", session_dir, session, INDUCT_DIR);

      // create induction folder if it does not already exist

      if (keyspace == 0)
      {
        if (rmdir (induction_directory) == -1)
        {
          if (errno == ENOENT)
          {
            // good, we can ignore
          }
          else if (errno == ENOTEMPTY)
          {
            char *induction_directory_mv = (char *) mymalloc (session_size);

            snprintf (induction_directory_mv, session_size - 1, "%s/%s.induct.%d", session_dir, session, (int) proc_start);

            if (rename (induction_directory, induction_directory_mv) != 0)
            {
              log_error ("ERROR: Rename directory %s to %s: %s", induction_directory, induction_directory_mv, strerror (errno));

              return -1;
            }
          }
          else
          {
            log_error ("ERROR: %s: %s", induction_directory, strerror (errno));

            return -1;
          }
        }

        if (mkdir (induction_directory, 0700) == -1)
        {
          log_error ("ERROR: %s: %s", induction_directory, strerror (errno));

          return -1;
        }
      }
    }
    else
    {
      induction_directory = induction_dir;
    }
  }

  data.induction_directory = induction_directory;

  /**
   * tuning db
   */

  char tuning_db_file[256] = { 0 };

  snprintf (tuning_db_file, sizeof (tuning_db_file) - 1, "%s/%s", shared_dir, TUNING_DB_FILE);

  tuning_db_t *tuning_db = tuning_db_init (tuning_db_file);

  /**
   * outfile-check directory
   */

  char *outfile_check_directory = NULL;

  if (outfile_check_dir == NULL)
  {
    outfile_check_directory = (char *) mymalloc (session_size);

    snprintf (outfile_check_directory, session_size - 1, "%s/%s.%s", session_dir, session, OUTFILES_DIR);
  }
  else
  {
    outfile_check_directory = outfile_check_dir;
  }

  data.outfile_check_directory = outfile_check_directory;

  if (keyspace == 0)
  {
    struct stat outfile_check_stat;

    if (stat (outfile_check_directory, &outfile_check_stat) == 0)
    {
      uint is_dir = S_ISDIR (outfile_check_stat.st_mode);

      if (is_dir == 0)
      {
        log_error ("ERROR: Directory specified in outfile-check '%s' is not a valid directory", outfile_check_directory);

        return -1;
      }
    }
    else if (outfile_check_dir == NULL)
    {
      if (mkdir (outfile_check_directory, 0700) == -1)
      {
        log_error ("ERROR: %s: %s", outfile_check_directory, strerror (errno));

        return -1;
      }
    }
  }

  /**
   * special other stuff
   */

  if (hash_mode == 9710)
  {
    outfile_format      = 5;
    outfile_format_chgd = 1;
  }

  if (hash_mode == 9810)
  {
    outfile_format      = 5;
    outfile_format_chgd = 1;
  }

  if (hash_mode == 10410)
  {
    outfile_format      = 5;
    outfile_format_chgd = 1;
  }

  /**
   * store stuff
   */

  data.restore                 = restore;
  data.restore_timer           = restore_timer;
  data.restore_disable         = restore_disable;
  data.status                  = status;
  data.status_timer            = status_timer;
  data.machine_readable        = machine_readable;
  data.loopback                = loopback;
  data.runtime                 = runtime;
  data.remove                  = remove;
  data.remove_timer            = remove_timer;
  data.debug_mode              = debug_mode;
  data.debug_file              = debug_file;
  data.username                = username;
  data.quiet                   = quiet;

  data.hex_charset             = hex_charset;
  data.hex_salt                = hex_salt;
  data.hex_wordlist            = hex_wordlist;
  data.rp_files                = rp_files;
  data.rp_files_cnt            = rp_files_cnt;
  data.rp_gen                  = rp_gen;
  data.rp_gen_seed             = rp_gen_seed;
  data.force                   = force;
  data.benchmark               = benchmark;
  data.skip                    = skip;
  data.limit                   = limit;
  data.custom_charset_1        = custom_charset_1;
  data.custom_charset_2        = custom_charset_2;
  data.custom_charset_3        = custom_charset_3;
  data.custom_charset_4        = custom_charset_4;
  #if defined (HAVE_HWMONO)
  data.powertune_enable        = powertune_enable;
  #endif
  data.logfile_disable         = logfile_disable;
  data.truecrypt_keyfiles      = truecrypt_keyfiles;
  data.veracrypt_keyfiles      = veracrypt_keyfiles;
  data.veracrypt_pim           = veracrypt_pim;
  data.scrypt_tmto             = scrypt_tmto;
  data.workload_profile        = workload_profile;

  /**
   * cpu affinity
   */

  if (cpu_affinity)
  {
    set_cpu_affinity (cpu_affinity);
  }

  if (rp_gen_seed_chgd == 0)
  {
    srand (proc_start);
  }
  else
  {
    srand (rp_gen_seed);
  }

  /**
   * logfile init
   */

  if (logfile_disable == 0)
  {
    size_t logfile_size = strlen (session_dir) + 1 + strlen (session) + 32;

    char *logfile = (char *) mymalloc (logfile_size);

    snprintf (logfile, logfile_size - 1, "%s/%s.log", session_dir, session);

    data.logfile = logfile;

    char *topid = logfile_generate_topid ();

    data.topid = topid;
  }

  logfile_top_msg ("START");

  logfile_top_uint   (attack_mode);
  logfile_top_uint   (attack_kern);
  logfile_top_uint   (benchmark);
  logfile_top_uint   (stdout_flag);
  logfile_top_uint   (bitmap_min);
  logfile_top_uint   (bitmap_max);
  logfile_top_uint   (debug_mode);
  logfile_top_uint   (force);
  logfile_top_uint   (kernel_accel);
  logfile_top_uint   (kernel_loops);
  logfile_top_uint   (nvidia_spin_damp);
  logfile_top_uint   (gpu_temp_disable);
  #if defined (HAVE_HWMON)
  logfile_top_uint   (gpu_temp_abort);
  logfile_top_uint   (gpu_temp_retain);
  #endif
  logfile_top_uint   (hash_mode);
  logfile_top_uint   (hex_charset);
  logfile_top_uint   (hex_salt);
  logfile_top_uint   (hex_wordlist);
  logfile_top_uint   (increment);
  logfile_top_uint   (increment_max);
  logfile_top_uint   (increment_min);
  logfile_top_uint   (keyspace);
  logfile_top_uint   (left);
  logfile_top_uint   (logfile_disable);
  logfile_top_uint   (loopback);
  logfile_top_uint   (markov_classic);
  logfile_top_uint   (markov_disable);
  logfile_top_uint   (markov_threshold);
  logfile_top_uint   (outfile_autohex);
  logfile_top_uint   (outfile_check_timer);
  logfile_top_uint   (outfile_format);
  logfile_top_uint   (potfile_disable);
  logfile_top_string (potfile_path);
  #if defined(HAVE_HWMON)
  logfile_top_uint   (powertune_enable);
  #endif
  logfile_top_uint   (scrypt_tmto);
  logfile_top_uint   (quiet);
  logfile_top_uint   (remove);
  logfile_top_uint   (remove_timer);
  logfile_top_uint   (restore);
  logfile_top_uint   (restore_disable);
  logfile_top_uint   (restore_timer);
  logfile_top_uint   (rp_gen);
  logfile_top_uint   (rp_gen_func_max);
  logfile_top_uint   (rp_gen_func_min);
  logfile_top_uint   (rp_gen_seed);
  logfile_top_uint   (runtime);
  logfile_top_uint   (segment_size);
  logfile_top_uint   (show);
  logfile_top_uint   (status);
  logfile_top_uint   (machine_readable);
  logfile_top_uint   (status_timer);
  logfile_top_uint   (usage);
  logfile_top_uint   (username);
  logfile_top_uint   (version);
  logfile_top_uint   (weak_hash_threshold);
  logfile_top_uint   (workload_profile);
  logfile_top_uint64 (limit);
  logfile_top_uint64 (skip);
  logfile_top_char   (separator);
  logfile_top_string (cpu_affinity);
  logfile_top_string (custom_charset_1);
  logfile_top_string (custom_charset_2);
  logfile_top_string (custom_charset_3);
  logfile_top_string (custom_charset_4);
  logfile_top_string (debug_file);
  logfile_top_string (opencl_devices);
  logfile_top_string (opencl_platforms);
  logfile_top_string (opencl_device_types);
  logfile_top_uint   (opencl_vector_width);
  logfile_top_string (induction_dir);
  logfile_top_string (markov_hcstat);
  logfile_top_string (outfile);
  logfile_top_string (outfile_check_dir);
  logfile_top_string (rule_buf_l);
  logfile_top_string (rule_buf_r);
  logfile_top_string (session);
  logfile_top_string (truecrypt_keyfiles);
  logfile_top_string (veracrypt_keyfiles);
  logfile_top_uint   (veracrypt_pim);

  /**
   * Init OpenCL library loader
   */

  if (keyspace == 0)
  {
    ocl = (OCL_PTR *) mymalloc (sizeof (OCL_PTR));

    ocl_init (ocl);

    data.ocl = ocl;
  }

  /**
   * OpenCL platform selection
   */

  u32 opencl_platforms_filter = setup_opencl_platforms_filter (opencl_platforms);

  /**
   * OpenCL device selection
   */

  u32 devices_filter = setup_devices_filter (opencl_devices);

  /**
   * OpenCL device type selection
   */

  cl_device_type device_types_filter = setup_device_types_filter (opencl_device_types);

  /**
   * benchmark
   */

  if (benchmark == 1)
  {
    /**
     * disable useless stuff for benchmark
     */

    status_timer          = 0;
    restore_timer         = 0;
    restore_disable       = 1;
    potfile_disable       = 1;
    weak_hash_threshold   = 0;
    nvidia_spin_damp      = 0;
    gpu_temp_disable      = 1;
    outfile_check_timer   = 0;

    #if defined (HAVE_HWMON)
    if (powertune_enable == 1)
    {
      gpu_temp_disable = 0;
    }
    #endif

    data.status_timer         = status_timer;
    data.restore_timer        = restore_timer;
    data.restore_disable      = restore_disable;
    data.outfile_check_timer  = outfile_check_timer;

    /**
     * force attack mode to be bruteforce
     */

    attack_mode = ATTACK_MODE_BF;
    attack_kern = ATTACK_KERN_BF;

    if (workload_profile_chgd == 0)
    {
      workload_profile = 3;

      data.workload_profile = workload_profile;
    }
  }

  data.attack_mode = attack_mode;
  data.attack_kern = attack_kern;

  /**
   * status, monitor and outfile remove threads
   */

  uint wordlist_mode = ((optind + 1) < myargc) ? WL_MODE_FILE : WL_MODE_STDIN;

  data.wordlist_mode = wordlist_mode;

  if (wordlist_mode == WL_MODE_STDIN)
  {
    // enable status (in stdin mode) whenever we do not use --stdout together with an outfile

    if      (stdout_flag == 0) status = 1;
    else if (outfile != NULL)  status = 1;

    data.status = status;
  }

  uint outer_threads_cnt = 0;

  hc_thread_t *outer_threads = (hc_thread_t *) mycalloc (10, sizeof (hc_thread_t));

  data.shutdown_outer = 0;

  if (keyspace == 0 && benchmark == 0 && stdout_flag == 0)
  {
    if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
    {
      hc_thread_create (outer_threads[outer_threads_cnt], thread_keypress, NULL);

      outer_threads_cnt++;
    }
  }

  /**
   * config
   */

  hashconfig_t *hashconfig = (hashconfig_t *) mymalloc (sizeof (hashconfig_t));

  data.hashconfig = hashconfig;

  uint algorithm_pos = 0;
  uint algorithm_max = 1;

  const int *algorithms = DEFAULT_BENCHMARK_ALGORITHMS_BUF;

  if (benchmark == 1 && hash_mode_chgd == 0) algorithm_max = DEFAULT_BENCHMARK_ALGORITHMS_CNT;

  for (algorithm_pos = 0; algorithm_pos < algorithm_max; algorithm_pos++)
  {
    /*
     * We need to reset 'rd' in benchmark mode otherwise when the user hits 'bypass'
     * the following algos are skipped entirely
     */

    if (algorithm_pos > 0)
    {
      local_free (rd);

      rd = init_restore (argc, argv);

      data.rd = rd;
    }

    /**
     * update hash_mode in case of multihash benchmark
     */

    if (benchmark == 1)
    {
      if (hash_mode_chgd == 0)
      {
        hash_mode = algorithms[algorithm_pos];
      }

      quiet = 1;

      data.quiet = quiet;
    }

    int rc = hashconfig_init (hashconfig, hash_mode, separator, hex_salt);

    if (rc == -1)
    {
      return -1;
    }

    /**
     * choose dictionary parser
     */

    get_next_word_func = get_next_word_std;

    if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
    {
      get_next_word_func = get_next_word_uc;
    }

    if (hashconfig->hash_type == HASH_TYPE_LM) // yes that's fine that way
    {
      get_next_word_func = get_next_word_lm;
    }

    /**
     * dictstat
     */

    dictstat_ctx_t *dictstat_ctx = mymalloc (sizeof (dictstat_ctx_t));

    dictstat_init (dictstat_ctx, profile_dir);

    if (keyspace == 0)
    {
      dictstat_read (dictstat_ctx);
    }

    /**
     * outfile
     */

    outfile_ctx_t *outfile_ctx = mymalloc (sizeof (outfile_ctx_t));

    data.outfile_ctx = outfile_ctx;

    outfile_init (outfile_ctx, outfile, outfile_format, outfile_autohex);

    if (show == 1 || left == 1)
    {
      outfile_write_open (outfile_ctx);
    }

    /**
     * potfile
     */

    potfile_ctx_t *potfile_ctx = mymalloc (sizeof (potfile_ctx_t));

    data.potfile_ctx = potfile_ctx;

    potfile_init (potfile_ctx, profile_dir, potfile_path);

    if (show == 1 || left == 1)
    {
      SUPPRESS_OUTPUT = 1;

      int rc = potfile_read_open (potfile_ctx);

      if (rc == -1) return -1;

      potfile_read_parse (potfile_ctx, hashconfig);

      potfile_read_close (potfile_ctx);

      SUPPRESS_OUTPUT = 0;
    }

    /**
     * loopback
     */

    loopback_ctx_t *loopback_ctx = mymalloc (sizeof (loopback_ctx_t));

    data.loopback_ctx = loopback_ctx;

    loopback_init (loopback_ctx);

    /**
     * word len
     */

    uint pw_min = hashconfig_general_pw_min (hashconfig);
    uint pw_max = hashconfig_general_pw_max (hashconfig);

    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      switch (attack_kern)
      {
        case ATTACK_KERN_STRAIGHT:  if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                    break;
        case ATTACK_KERN_COMBI:     if (pw_max > PW_DICTMAX) pw_max = PW_DICTMAX1;
                                    break;
      }
    }

    /**
     * charsets : keep them together for more easy maintainnce
     */

    cs_t mp_sys[6] = { { { 0 }, 0 } };
    cs_t mp_usr[4] = { { { 0 }, 0 } };

    mp_setup_sys (mp_sys);

    if (custom_charset_1) mp_setup_usr (mp_sys, mp_usr, custom_charset_1, 0, hashconfig);
    if (custom_charset_2) mp_setup_usr (mp_sys, mp_usr, custom_charset_2, 1, hashconfig);
    if (custom_charset_3) mp_setup_usr (mp_sys, mp_usr, custom_charset_3, 2, hashconfig);
    if (custom_charset_4) mp_setup_usr (mp_sys, mp_usr, custom_charset_4, 3, hashconfig);

    /**
     * load hashes, part I: find input mode, count hashes
     */

    uint hashlist_mode   = 0;
    uint hashlist_format = HLFMT_HASHCAT;

    uint hashes_avail = 0;

    if ((benchmark == 0) && (stdout_flag == 0))
    {
      struct stat f;

      hashlist_mode = (stat (myargv[optind], &f) == 0) ? HL_MODE_FILE : HL_MODE_ARG;

      if ((hashconfig->hash_mode == 2500) ||
          (hashconfig->hash_mode == 5200) ||
          ((hashconfig->hash_mode >=  6200) && (hashconfig->hash_mode <=  6299)) ||
          ((hashconfig->hash_mode >= 13700) && (hashconfig->hash_mode <= 13799)) ||
          (hashconfig->hash_mode == 9000))
      {
        hashlist_mode = HL_MODE_ARG;

        char *hashfile = myargv[optind];

        data.hashfile = hashfile;

        logfile_top_var_string ("target", hashfile);
      }

      if (hashlist_mode == HL_MODE_ARG)
      {
        if (hashconfig->hash_mode == 2500)
        {
          struct stat st;

          if (stat (data.hashfile, &st) == -1)
          {
            log_error ("ERROR: %s: %s", data.hashfile, strerror (errno));

            return -1;
          }

          hashes_avail = st.st_size / sizeof (hccap_t);
        }
        else
        {
          hashes_avail = 1;
        }
      }
      else if (hashlist_mode == HL_MODE_FILE)
      {
        char *hashfile = myargv[optind];

        data.hashfile = hashfile;

        logfile_top_var_string ("target", hashfile);

        FILE *fp = NULL;

        if ((fp = fopen (hashfile, "rb")) == NULL)
        {
          log_error ("ERROR: %s: %s", hashfile, strerror (errno));

          return -1;
        }

        if (data.quiet == 0) log_info_nn ("Counting lines in %s", hashfile);

        hashes_avail = count_lines (fp);

        rewind (fp);

        if (hashes_avail == 0)
        {
          log_error ("ERROR: hashfile is empty or corrupt");

          fclose (fp);

          return -1;
        }

        hashlist_format = hlfmt_detect (fp, 100, hashconfig); // 100 = max numbers to "scan". could be hashes_avail, too

        if ((remove == 1) && (hashlist_format != HLFMT_HASHCAT))
        {
          log_error ("ERROR: remove not supported in native hashfile-format mode");

          fclose (fp);

          return -1;
        }

        fclose (fp);
      }
    }
    else
    {
      hashlist_mode = HL_MODE_ARG;

      hashes_avail = 1;
    }

    if (hashconfig->hash_mode == 3000) hashes_avail *= 2;

    data.hashlist_mode   = hashlist_mode;
    data.hashlist_format = hashlist_format;

    logfile_top_uint (hashlist_mode);
    logfile_top_uint (hashlist_format);

    /**
     * load hashes, part II: allocate required memory, set pointers
     */

    hash_t *hashes_buf  = NULL;
    void   *digests_buf = NULL;
    salt_t *salts_buf   = NULL;
    void   *esalts_buf  = NULL;

    hashes_buf = (hash_t *) mycalloc (hashes_avail, sizeof (hash_t));

    digests_buf = (void *) mycalloc (hashes_avail, hashconfig->dgst_size);

    if ((username && (remove || show)) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY))
    {
      u32 hash_pos;

      for (hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
      {
        hashinfo_t *hash_info = (hashinfo_t *) mymalloc (sizeof (hashinfo_t));

        hashes_buf[hash_pos].hash_info = hash_info;

        if (username && (remove || show || left))
        {
          hash_info->user = (user_t*) mymalloc (sizeof (user_t));
        }

        if (benchmark)
        {
          hash_info->orighash = (char *) mymalloc (256);
        }
      }
    }

    if (hashconfig->is_salted)
    {
      salts_buf = (salt_t *) mycalloc (hashes_avail, sizeof (salt_t));

      if (hashconfig->esalt_size)
      {
        esalts_buf = (void *) mycalloc (hashes_avail, hashconfig->esalt_size);
      }
    }
    else
    {
      salts_buf = (salt_t *) mycalloc (1, sizeof (salt_t));
    }

    for (uint hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
    {
      hashes_buf[hash_pos].digest = ((char *) digests_buf) + (hash_pos * hashconfig->dgst_size);

      if (hashconfig->is_salted)
      {
        hashes_buf[hash_pos].salt = &salts_buf[hash_pos];

        if (hashconfig->esalt_size)
        {
          hashes_buf[hash_pos].esalt = ((char *) esalts_buf) + (hash_pos * hashconfig->esalt_size);
        }
      }
      else
      {
        hashes_buf[hash_pos].salt = &salts_buf[0];
      }
    }

    /**
     * load hashes, part III: parse hashes or generate them if benchmark
     */

    uint hashes_cnt = 0;

    if (benchmark == 0)
    {
      if (keyspace == 1)
      {
        // useless to read hash file for keyspace, cheat a little bit w/ optind
      }
      else if (stdout_flag == 1)
      {
        // useless to read hash file for stdout, cheat a little bit w/ optind
      }
      else if (hashes_avail == 0)
      {
      }
      else if (hashlist_mode == HL_MODE_ARG)
      {
        char *input_buf = myargv[optind];

        uint input_len = strlen (input_buf);

        logfile_top_var_string ("target", input_buf);

        char *hash_buf = NULL;
        int   hash_len = 0;

        hlfmt_hash (hashlist_format, input_buf, input_len, &hash_buf, &hash_len, hashconfig);

        bool hash_fmt_error = 0;

        if (hash_len < 1)     hash_fmt_error = 1;
        if (hash_buf == NULL) hash_fmt_error = 1;

        if (hash_fmt_error)
        {
          log_info ("WARNING: Failed to parse hashes using the '%s' format", strhlfmt (hashlist_format));
        }
        else
        {
          if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)
          {
            hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

            hash_info_tmp->orighash = mystrdup (hash_buf);
          }

          if (hashconfig->is_salted)
          {
            memset (hashes_buf[0].salt, 0, sizeof (salt_t));
          }

          int parser_status = PARSER_OK;

          if (hashconfig->hash_mode == 2500)
          {
            if (hash_len == 0)
            {
              log_error ("ERROR: hccap file not specified");

              return -1;
            }

            hashlist_mode = HL_MODE_FILE;

            data.hashlist_mode = hashlist_mode;

            FILE *fp = fopen (hash_buf, "rb");

            if (fp == NULL)
            {
              log_error ("ERROR: %s: %s", hash_buf, strerror (errno));

              return -1;
            }

            if (hashes_avail < 1)
            {
              log_error ("ERROR: hccap file is empty or corrupt");

              fclose (fp);

              return -1;
            }

            uint hccap_size = sizeof (hccap_t);

            char *in = (char *) mymalloc (hccap_size);

            while (!feof (fp))
            {
              int n = fread (in, hccap_size, 1, fp);

              if (n != 1)
              {
                if (hashes_cnt < 1) parser_status = PARSER_HCCAP_FILE_SIZE;

                break;
              }

              parser_status = hashconfig->parse_func (in, hccap_size, &hashes_buf[hashes_cnt], hashconfig);

              if (parser_status != PARSER_OK)
              {
                log_info ("WARNING: Hash '%s': %s", hash_buf, strparser (parser_status));

                continue;
              }

              // hack: append MAC1 and MAC2 s.t. in --show and --left the line matches with the .pot file format (i.e. ESSID:MAC1:MAC2)

              if ((show == 1) || (left == 1))
              {
                salt_t *tmp_salt = hashes_buf[hashes_cnt].salt;

                char *salt_ptr = (char *) tmp_salt->salt_buf;

                int cur_pos = tmp_salt->salt_len;
                int rem_len = sizeof (hashes_buf[hashes_cnt].salt->salt_buf) - cur_pos;

                wpa_t *wpa = (wpa_t *) hashes_buf[hashes_cnt].esalt;

                // do the appending task

                snprintf (salt_ptr + cur_pos,
                          rem_len,
                          ":%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x",
                          wpa->orig_mac1[0],
                          wpa->orig_mac1[1],
                          wpa->orig_mac1[2],
                          wpa->orig_mac1[3],
                          wpa->orig_mac1[4],
                          wpa->orig_mac1[5],
                          wpa->orig_mac2[0],
                          wpa->orig_mac2[1],
                          wpa->orig_mac2[2],
                          wpa->orig_mac2[3],
                          wpa->orig_mac2[4],
                          wpa->orig_mac2[5]);

                // memset () the remaining part of the salt

                cur_pos = tmp_salt->salt_len + 1 + 12 + 1 + 12;
                rem_len = sizeof (hashes_buf[hashes_cnt].salt->salt_buf) - cur_pos;

                if (rem_len > 0) memset (salt_ptr + cur_pos, 0, rem_len);

                tmp_salt->salt_len += 1 + 12 + 1 + 12;
              }

              if (show == 1) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, (char *) hashes_buf[hashes_cnt].salt->salt_buf, hashes_buf[hashes_cnt].salt->salt_len, &hashes_buf[hashes_cnt], sort_by_salt_buf);
              if (left == 1) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, (char *) hashes_buf[hashes_cnt].salt->salt_buf, hashes_buf[hashes_cnt].salt->salt_len, &hashes_buf[hashes_cnt], sort_by_salt_buf);

              hashes_cnt++;
            }

            fclose (fp);

            myfree (in);
          }
          else if (hashconfig->hash_mode == 3000)
          {
            if (hash_len == 32)
            {
              parser_status = hashconfig->parse_func (hash_buf, 16, &hashes_buf[hashes_cnt], hashconfig);

              hash_t *lm_hash_left = NULL;

              if (parser_status == PARSER_OK)
              {
                lm_hash_left = &hashes_buf[hashes_cnt];

                hashes_cnt++;
              }
              else
              {
                log_info ("WARNING: Hash '%s': %s", input_buf, strparser (parser_status));
              }

              parser_status = hashconfig->parse_func (hash_buf + 16, 16, &hashes_buf[hashes_cnt], hashconfig);

              hash_t *lm_hash_right = NULL;

              if (parser_status == PARSER_OK)
              {
                lm_hash_right = &hashes_buf[hashes_cnt];

                hashes_cnt++;
              }
              else
              {
                log_info ("WARNING: Hash '%s': %s", input_buf, strparser (parser_status));
              }

              // show / left

              if ((lm_hash_left != NULL) && (lm_hash_right != NULL))
              {
                if (show == 1) potfile_show_request_lm (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, lm_hash_left, lm_hash_right, sort_by_pot);
                if (left == 1) potfile_left_request_lm (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, lm_hash_left, lm_hash_right, sort_by_pot);
              }
            }
            else
            {
              parser_status = hashconfig->parse_func (hash_buf, hash_len, &hashes_buf[hashes_cnt], hashconfig);

              if (parser_status == PARSER_OK)
              {
                if (show == 1) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, &hashes_buf[hashes_cnt], sort_by_pot);
                if (left == 1) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, &hashes_buf[hashes_cnt], sort_by_pot);
              }

              if (parser_status == PARSER_OK)
              {
                hashes_cnt++;
              }
              else
              {
                log_info ("WARNING: Hash '%s': %s", input_buf, strparser (parser_status));
              }
            }
          }
          else
          {
            parser_status = hashconfig->parse_func (hash_buf, hash_len, &hashes_buf[hashes_cnt], hashconfig);

            if (parser_status == PARSER_OK)
            {
              if (show == 1) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, &hashes_buf[hashes_cnt], sort_by_pot);
              if (left == 1) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, input_buf, input_len, &hashes_buf[hashes_cnt], sort_by_pot);
            }

            if (parser_status == PARSER_OK)
            {
              hashes_cnt++;
            }
            else
            {
              log_info ("WARNING: Hash '%s': %s", input_buf, strparser (parser_status));
            }
          }
        }
      }
      else if (hashlist_mode == HL_MODE_FILE)
      {
        char *hashfile = data.hashfile;

        FILE *fp;

        if ((fp = fopen (hashfile, "rb")) == NULL)
        {
          log_error ("ERROR: %s: %s", hashfile, strerror (errno));

          return -1;
        }

        uint line_num = 0;

        char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

        while (!feof (fp))
        {
          line_num++;

          int line_len = fgetl (fp, line_buf);

          if (line_len == 0) continue;

          char *hash_buf = NULL;
          int   hash_len = 0;

          hlfmt_hash (hashlist_format, line_buf, line_len, &hash_buf, &hash_len, hashconfig);

          bool hash_fmt_error = 0;

          if (hash_len < 1)     hash_fmt_error = 1;
          if (hash_buf == NULL) hash_fmt_error = 1;

          if (hash_fmt_error)
          {
            log_info ("WARNING: failed to parse hashes using the '%s' format", strhlfmt (hashlist_format));

            continue;
          }

          if (username)
          {
            char *user_buf = NULL;
            int   user_len = 0;

            hlfmt_user (hashlist_format, line_buf, line_len, &user_buf, &user_len, hashconfig);

            if (remove || show)
            {
              user_t **user = &hashes_buf[hashes_cnt].hash_info->user;

              *user = (user_t *) mymalloc (sizeof (user_t));

              user_t *user_ptr = *user;

              if (user_buf != NULL)
              {
                user_ptr->user_name = mystrdup (user_buf);
              }
              else
              {
                user_ptr->user_name = mystrdup ("");
              }

              user_ptr->user_len = user_len;
            }
          }

          if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)
          {
            hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

            hash_info_tmp->orighash = mystrdup (hash_buf);
          }

          if (hashconfig->is_salted)
          {
            memset (hashes_buf[hashes_cnt].salt, 0, sizeof (salt_t));
          }

          if (hashconfig->hash_mode == 3000)
          {
            if (hash_len == 32)
            {
              int parser_status = hashconfig->parse_func (hash_buf, 16, &hashes_buf[hashes_cnt], hashconfig);

              if (parser_status < PARSER_GLOBAL_ZERO)
              {
                log_info ("WARNING: Hashfile '%s' on line %u (%s): %s", data.hashfile, line_num, line_buf, strparser (parser_status));

                continue;
              }

              hash_t *lm_hash_left = &hashes_buf[hashes_cnt];

              hashes_cnt++;

              parser_status = hashconfig->parse_func (hash_buf + 16, 16, &hashes_buf[hashes_cnt], hashconfig);

              if (parser_status < PARSER_GLOBAL_ZERO)
              {
                log_info ("WARNING: Hashfile '%s' on line %u (%s): %s", data.hashfile, line_num, line_buf, strparser (parser_status));

                continue;
              }

              hash_t *lm_hash_right = &hashes_buf[hashes_cnt];

              if (data.quiet == 0) if ((hashes_cnt % 0x20000) == 0) log_info_nn ("Parsed Hashes: %u/%u (%0.2f%%)", hashes_cnt, hashes_avail, ((double) hashes_cnt / hashes_avail) * 100);

              hashes_cnt++;

              // show / left

              if (show == 1) potfile_show_request_lm (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, lm_hash_left, lm_hash_right, sort_by_pot);
              if (left == 1) potfile_left_request_lm (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, lm_hash_left, lm_hash_right, sort_by_pot);
            }
            else
            {
              int parser_status = hashconfig->parse_func (hash_buf, hash_len, &hashes_buf[hashes_cnt], hashconfig);

              if (parser_status < PARSER_GLOBAL_ZERO)
              {
                log_info ("WARNING: Hashfile '%s' on line %u (%s): %s", data.hashfile, line_num, line_buf, strparser (parser_status));

                continue;
              }

              if (data.quiet == 0) if ((hashes_cnt % 0x20000) == 0) log_info_nn ("Parsed Hashes: %u/%u (%0.2f%%)", hashes_cnt, hashes_avail, ((double) hashes_cnt / hashes_avail) * 100);

              if (show == 1) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, &hashes_buf[hashes_cnt], sort_by_pot);
              if (left == 1) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, &hashes_buf[hashes_cnt], sort_by_pot);

              hashes_cnt++;
            }
          }
          else
          {
            int parser_status = hashconfig->parse_func (hash_buf, hash_len, &hashes_buf[hashes_cnt], hashconfig);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              log_info ("WARNING: Hashfile '%s' on line %u (%s): %s", data.hashfile, line_num, line_buf, strparser (parser_status));

              continue;
            }

            if (data.quiet == 0) if ((hashes_cnt % 0x20000) == 0) log_info_nn ("Parsed Hashes: %u/%u (%0.2f%%)", hashes_cnt, hashes_avail, ((double) hashes_cnt / hashes_avail) * 100);

            if (show == 1) potfile_show_request (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, &hashes_buf[hashes_cnt], sort_by_pot);
            if (left == 1) potfile_left_request (potfile_ctx, hashconfig, outfile_ctx, line_buf, line_len, &hashes_buf[hashes_cnt], sort_by_pot);

            hashes_cnt++;
          }
        }

        myfree (line_buf);

        fclose (fp);

        if (data.quiet == 0) log_info_nn ("Parsed Hashes: %u/%u (%0.2f%%)", hashes_avail, hashes_avail, 100.00);
      }
    }
    else
    {
      hashconfig_benchmark_defaults (hashconfig, hashes_buf[0].salt, hashes_buf[0].esalt);

      data.hashfile = "-";

      hashes_cnt = 1;
    }

    if (show == 1 || left == 1)
    {
      outfile_write_close (outfile_ctx);

      potfile_hash_free (potfile_ctx, hashconfig);

      if (data.quiet == 0) log_info_nn ("");

      return 0;
    }

    if ((keyspace == 0) && (stdout_flag == 0))
    {
      if (hashes_cnt == 0)
      {
        log_error ("ERROR: No hashes loaded");

        return -1;
      }
    }

    /**
     * Sanity check for hashfile vs outfile (should not point to the same physical file)
     */

    if (outfile != NULL)
    {
      char *hashfile = data.hashfile;

      if (hashfile != NULL)
      {
        #if defined (_POSIX)
        struct stat tmpstat_outfile;
        struct stat tmpstat_hashfile;
        #endif

        #if defined (_WIN)
        struct stat64 tmpstat_outfile;
        struct stat64 tmpstat_hashfile;
        #endif

        FILE *tmp_outfile_fp = fopen (outfile, "r");

        if (tmp_outfile_fp)
        {
          #if defined (_POSIX)
          fstat (fileno (tmp_outfile_fp), &tmpstat_outfile);
          #endif

          #if defined (_WIN)
          _fstat64 (fileno (tmp_outfile_fp), &tmpstat_outfile);
          #endif

          fclose (tmp_outfile_fp);
        }

        FILE *tmp_hashfile_fp = fopen (hashfile, "r");

        if (tmp_hashfile_fp)
        {
          #if defined (_POSIX)
          fstat (fileno (tmp_hashfile_fp), &tmpstat_hashfile);
          #endif

          #if defined (_WIN)
          _fstat64 (fileno (tmp_hashfile_fp), &tmpstat_hashfile);
          #endif

          fclose (tmp_hashfile_fp);
        }

        if (tmp_outfile_fp && tmp_outfile_fp)
        {
          tmpstat_outfile.st_mode     = 0;
          tmpstat_outfile.st_nlink    = 0;
          tmpstat_outfile.st_uid      = 0;
          tmpstat_outfile.st_gid      = 0;
          tmpstat_outfile.st_rdev     = 0;
          tmpstat_outfile.st_atime    = 0;

          tmpstat_hashfile.st_mode    = 0;
          tmpstat_hashfile.st_nlink   = 0;
          tmpstat_hashfile.st_uid     = 0;
          tmpstat_hashfile.st_gid     = 0;
          tmpstat_hashfile.st_rdev    = 0;
          tmpstat_hashfile.st_atime   = 0;

          #if defined (_POSIX)
          tmpstat_outfile.st_blksize  = 0;
          tmpstat_outfile.st_blocks   = 0;

          tmpstat_hashfile.st_blksize = 0;
          tmpstat_hashfile.st_blocks  = 0;
          #endif

          #if defined (_POSIX)
          if (memcmp (&tmpstat_outfile, &tmpstat_hashfile, sizeof (struct stat)) == 0)
          {
            log_error ("ERROR: Hashfile and Outfile are not allowed to point to the same file");

            return -1;
          }
          #endif

          #if defined (_WIN)
          if (memcmp (&tmpstat_outfile, &tmpstat_hashfile, sizeof (struct stat64)) == 0)
          {
            log_error ("ERROR: Hashfile and Outfile are not allowed to point to the same file");

            return -1;
          }
          #endif
        }
      }
    }

    /**
     * Remove duplicates
     */

    if (data.quiet == 0) log_info_nn ("Removing duplicate hashes...");

    if (hashconfig->is_salted)
    {
      qsort (hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash);
    }
    else
    {
      qsort (hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_no_salt);
    }

    uint hashes_cnt_orig = hashes_cnt;

    hashes_cnt = 1;

    for (uint hashes_pos = 1; hashes_pos < hashes_cnt_orig; hashes_pos++)
    {
      if (hashconfig->is_salted)
      {
        if (sort_by_salt (hashes_buf[hashes_pos].salt, hashes_buf[hashes_pos - 1].salt) == 0)
        {
          if (sort_by_digest_p0p1 (hashes_buf[hashes_pos].digest, hashes_buf[hashes_pos - 1].digest) == 0) continue;
        }
      }
      else
      {
        if (sort_by_digest_p0p1 (hashes_buf[hashes_pos].digest, hashes_buf[hashes_pos - 1].digest) == 0) continue;
      }

      if (hashes_pos > hashes_cnt)
      {
        memcpy (&hashes_buf[hashes_cnt], &hashes_buf[hashes_pos], sizeof (hash_t));
      }

      hashes_cnt++;
    }

    /**
     * Potfile removes
     */

    int potfile_remove_cracks = 0;

    if (potfile_disable == 0)
    {
      if (data.quiet == 0) log_info_nn ("Comparing hashes with potfile entries...");

      potfile_remove_cracks = potfile_remove_parse (potfile_ctx, hashconfig, hashes_buf, hashes_cnt);
    }

    /**
     * Now generate all the buffers required for later
     */

    void   *digests_buf_new = (void *) mycalloc (hashes_avail, hashconfig->dgst_size);

    salt_t *salts_buf_new  = NULL;
    void   *esalts_buf_new = NULL;

    if (hashconfig->is_salted)
    {
      salts_buf_new = (salt_t *) mycalloc (hashes_avail, sizeof (salt_t));

      if (hashconfig->esalt_size)
      {
        esalts_buf_new = (void *) mycalloc (hashes_avail, hashconfig->esalt_size);
      }
    }
    else
    {
      salts_buf_new = (salt_t *) mycalloc (1, sizeof (salt_t));
    }

    if (data.quiet == 0) log_info_nn ("Structuring salts for cracking task...");

    uint digests_cnt  = hashes_cnt;
    uint digests_done = 0;

    size_t size_digests = digests_cnt * hashconfig->dgst_size;
    size_t size_shown   = digests_cnt * sizeof (uint);

    uint *digests_shown     = (uint *) mymalloc (size_shown);
    uint *digests_shown_tmp = (uint *) mymalloc (size_shown);

    uint salts_cnt   = 0;
    uint salts_done  = 0;

    hashinfo_t **hash_info = NULL;

    if ((username && (remove || show)) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY))
    {
      hash_info = (hashinfo_t **) mymalloc (hashes_cnt * sizeof (hashinfo_t *));

      if (username && (remove || show))
      {
        uint user_pos;

        for (user_pos = 0; user_pos < hashes_cnt; user_pos++)
        {
          hash_info[user_pos] = (hashinfo_t*) mycalloc (hashes_cnt, sizeof (hashinfo_t));

          hash_info[user_pos]->user = (user_t*) mymalloc (sizeof (user_t));
        }
      }
    }

    uint *salts_shown = (uint *) mymalloc (size_shown);

    salt_t *salt_buf;

    {
      // copied from inner loop

      salt_buf = &salts_buf_new[salts_cnt];

      memcpy (salt_buf, hashes_buf[0].salt, sizeof (salt_t));

      if (hashconfig->esalt_size)
      {
        memcpy (((char *) esalts_buf_new) + (salts_cnt * hashconfig->esalt_size), hashes_buf[0].esalt, hashconfig->esalt_size);
      }

      salt_buf->digests_cnt    = 0;
      salt_buf->digests_done   = 0;
      salt_buf->digests_offset = 0;

      salts_cnt++;
    }

    if (hashes_buf[0].cracked == 1)
    {
      digests_shown[0] = 1;

      digests_done++;

      salt_buf->digests_done++;
    }

    salt_buf->digests_cnt++;

    memcpy (((char *) digests_buf_new) + (0 * hashconfig->dgst_size), hashes_buf[0].digest, hashconfig->dgst_size);

    if ((username && (remove || show)) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY))
    {
      hash_info[0] = hashes_buf[0].hash_info;
    }

    // copy from inner loop

    for (uint hashes_pos = 1; hashes_pos < hashes_cnt; hashes_pos++)
    {
      if (hashconfig->is_salted)
      {
        if (sort_by_salt (hashes_buf[hashes_pos].salt, hashes_buf[hashes_pos - 1].salt) != 0)
        {
          salt_buf = &salts_buf_new[salts_cnt];

          memcpy (salt_buf, hashes_buf[hashes_pos].salt, sizeof (salt_t));

          if (hashconfig->esalt_size)
          {
            memcpy (((char *) esalts_buf_new) + (salts_cnt * hashconfig->esalt_size), hashes_buf[hashes_pos].esalt, hashconfig->esalt_size);
          }

          salt_buf->digests_cnt    = 0;
          salt_buf->digests_done   = 0;
          salt_buf->digests_offset = hashes_pos;

          salts_cnt++;
        }
      }

      if (hashes_buf[hashes_pos].cracked == 1)
      {
        digests_shown[hashes_pos] = 1;

        digests_done++;

        salt_buf->digests_done++;
      }

      salt_buf->digests_cnt++;

      memcpy (((char *) digests_buf_new) + (hashes_pos * hashconfig->dgst_size), hashes_buf[hashes_pos].digest, hashconfig->dgst_size);

      if ((username && (remove || show)) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY))
      {
        hash_info[hashes_pos] = hashes_buf[hashes_pos].hash_info;
      }
    }

    for (uint salt_pos = 0; salt_pos < salts_cnt; salt_pos++)
    {
      salt_t *salt_buf = &salts_buf_new[salt_pos];

      if (salt_buf->digests_done == salt_buf->digests_cnt)
      {
        salts_shown[salt_pos] = 1;

        salts_done++;
      }

      if (salts_done == salts_cnt) data.devices_status = STATUS_CRACKED;
    }

    local_free (digests_buf);
    local_free (salts_buf);
    local_free (esalts_buf);

    digests_buf = digests_buf_new;
    salts_buf   = salts_buf_new;
    esalts_buf  = esalts_buf_new;

    local_free (hashes_buf);

    char *optional_param1 = NULL;

    if (truecrypt_keyfiles) optional_param1 = truecrypt_keyfiles;
    if (veracrypt_keyfiles) optional_param1 = veracrypt_keyfiles;

    hashconfig_general_defaults (hashconfig, salts_buf, salts_cnt, esalts_buf, optional_param1);

    data.digests_cnt        = digests_cnt;
    data.digests_done       = digests_done;
    data.digests_buf        = digests_buf;
    data.digests_shown      = digests_shown;
    data.digests_shown_tmp  = digests_shown_tmp;

    data.salts_cnt          = salts_cnt;
    data.salts_done         = salts_done;
    data.salts_buf          = salts_buf;
    data.salts_shown        = salts_shown;

    data.esalts_buf         = esalts_buf;
    data.hash_info          = hash_info;

    /**
     * Automatic Optimizers
     */

    if (salts_cnt == 1)
      hashconfig->opti_type |= OPTI_TYPE_SINGLE_SALT;

    if (digests_cnt == 1)
      hashconfig->opti_type |= OPTI_TYPE_SINGLE_HASH;

    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      hashconfig->opti_type |= OPTI_TYPE_NOT_ITERATED;

    if (attack_mode == ATTACK_MODE_BF)
      hashconfig->opti_type |= OPTI_TYPE_BRUTE_FORCE;

    if (hashconfig->opti_type & OPTI_TYPE_BRUTE_FORCE)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
          {
            hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD80;
            hashconfig->opts_type |=  OPTS_TYPE_PT_ADD80;
          }

          if (hashconfig->opts_type & OPTS_TYPE_ST_ADDBITS14)
          {
            hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS14;
            hashconfig->opts_type |=  OPTS_TYPE_PT_ADDBITS14;
          }

          if (hashconfig->opts_type & OPTS_TYPE_ST_ADDBITS15)
          {
            hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS15;
            hashconfig->opts_type |=  OPTS_TYPE_PT_ADDBITS15;
          }
        }
      }
    }

    /**
     * Some algorithm, like descrypt, can benefit from JIT compilation
     */

    int force_jit_compilation = -1;

    if (hashconfig->hash_mode == 8900)
    {
      force_jit_compilation = 8900;
    }
    else if (hashconfig->hash_mode == 9300)
    {
      force_jit_compilation = 8900;
    }
    else if (hashconfig->hash_mode == 1500 && attack_mode == ATTACK_MODE_BF && data.salts_cnt == 1)
    {
      force_jit_compilation = 1500;
    }

    /**
     * generate bitmap tables
     */

    const uint bitmap_shift1 = 5;
    const uint bitmap_shift2 = 13;

    if (bitmap_max < bitmap_min) bitmap_max = bitmap_min;

    uint *bitmap_s1_a = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s1_b = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s1_c = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s1_d = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s2_a = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s2_b = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s2_c = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));
    uint *bitmap_s2_d = (uint *) mymalloc ((1u << bitmap_max) * sizeof (uint));

    uint bitmap_bits;
    uint bitmap_nums;
    uint bitmap_mask;
    uint bitmap_size;

    for (bitmap_bits = bitmap_min; bitmap_bits < bitmap_max; bitmap_bits++)
    {
      if (data.quiet == 0) log_info_nn ("Generating bitmap tables with %u bits...", bitmap_bits);

      bitmap_nums = 1u << bitmap_bits;

      bitmap_mask = bitmap_nums - 1;

      bitmap_size = bitmap_nums * sizeof (uint);

      if ((hashes_cnt & bitmap_mask) == hashes_cnt) break;

      if (generate_bitmaps (digests_cnt, hashconfig->dgst_size, bitmap_shift1, (char *) data.digests_buf, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, bitmap_mask, bitmap_size, bitmap_s1_a, bitmap_s1_b, bitmap_s1_c, bitmap_s1_d, digests_cnt / 2) == 0x7fffffff) continue;
      if (generate_bitmaps (digests_cnt, hashconfig->dgst_size, bitmap_shift2, (char *) data.digests_buf, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, bitmap_mask, bitmap_size, bitmap_s1_a, bitmap_s1_b, bitmap_s1_c, bitmap_s1_d, digests_cnt / 2) == 0x7fffffff) continue;

      break;
    }

    bitmap_nums = 1u << bitmap_bits;

    bitmap_mask = bitmap_nums - 1;

    bitmap_size = bitmap_nums * sizeof (uint);

    generate_bitmaps (digests_cnt, hashconfig->dgst_size, bitmap_shift1, (char *) data.digests_buf, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, bitmap_mask, bitmap_size, bitmap_s1_a, bitmap_s1_b, bitmap_s1_c, bitmap_s1_d, -1ul);
    generate_bitmaps (digests_cnt, hashconfig->dgst_size, bitmap_shift2, (char *) data.digests_buf, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, bitmap_mask, bitmap_size, bitmap_s2_a, bitmap_s2_b, bitmap_s2_c, bitmap_s2_d, -1ul);

    /**
     * prepare quick rule
     */

    data.rule_buf_l = rule_buf_l;
    data.rule_buf_r = rule_buf_r;

    int rule_len_l = (int) strlen (rule_buf_l);
    int rule_len_r = (int) strlen (rule_buf_r);

    data.rule_len_l = rule_len_l;
    data.rule_len_r = rule_len_r;

    /**
     * load rules
     */

    uint *all_kernel_rules_cnt = NULL;

    kernel_rule_t **all_kernel_rules_buf = NULL;

    if (rp_files_cnt)
    {
      all_kernel_rules_cnt = (uint *) mycalloc (rp_files_cnt, sizeof (uint));

      all_kernel_rules_buf = (kernel_rule_t **) mycalloc (rp_files_cnt, sizeof (kernel_rule_t *));
    }

    char *rule_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

    int rule_len = 0;

    for (uint i = 0; i < rp_files_cnt; i++)
    {
      uint kernel_rules_avail = 0;

      uint kernel_rules_cnt = 0;

      kernel_rule_t *kernel_rules_buf = NULL;

      char *rp_file = rp_files[i];

      char in[BLOCK_SIZE]  = { 0 };
      char out[BLOCK_SIZE] = { 0 };

      FILE *fp = NULL;

      uint rule_line = 0;

      if ((fp = fopen (rp_file, "rb")) == NULL)
      {
        log_error ("ERROR: %s: %s", rp_file, strerror (errno));

        return -1;
      }

      while (!feof (fp))
      {
        memset (rule_buf, 0, HCBUFSIZ_LARGE);

        rule_len = fgetl (fp, rule_buf);

        rule_line++;

        if (rule_len == 0) continue;

        if (rule_buf[0] == '#') continue;

        if (kernel_rules_avail == kernel_rules_cnt)
        {
          kernel_rules_buf = (kernel_rule_t *) myrealloc (kernel_rules_buf, kernel_rules_avail * sizeof (kernel_rule_t), INCR_RULES * sizeof (kernel_rule_t));

          kernel_rules_avail += INCR_RULES;
        }

        memset (in,  0, BLOCK_SIZE);
        memset (out, 0, BLOCK_SIZE);

        int result = _old_apply_rule (rule_buf, rule_len, in, 1, out);

        if (result == -1)
        {
          log_info ("WARNING: Skipping invalid or unsupported rule in file %s on line %u: %s", rp_file, rule_line, rule_buf);

          continue;
        }

        if (cpu_rule_to_kernel_rule (rule_buf, rule_len, &kernel_rules_buf[kernel_rules_cnt]) == -1)
        {
          log_info ("WARNING: Cannot convert rule for use on OpenCL device in file %s on line %u: %s", rp_file, rule_line, rule_buf);

          memset (&kernel_rules_buf[kernel_rules_cnt], 0, sizeof (kernel_rule_t)); // needs to be cleared otherwise we could have some remaining data

          continue;
        }

        kernel_rules_cnt++;
      }

      fclose (fp);

      all_kernel_rules_cnt[i] = kernel_rules_cnt;

      all_kernel_rules_buf[i] = kernel_rules_buf;
    }

    /**
     * merge rules or automatic rule generator
     */

    uint kernel_rules_cnt = 0;

    kernel_rule_t *kernel_rules_buf = NULL;

    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (rp_files_cnt)
      {
        kernel_rules_cnt = 1;

        uint *repeats = (uint *) mycalloc (rp_files_cnt + 1, sizeof (uint));

        repeats[0] = kernel_rules_cnt;

        for (uint i = 0; i < rp_files_cnt; i++)
        {
          kernel_rules_cnt *= all_kernel_rules_cnt[i];

          repeats[i + 1] = kernel_rules_cnt;
        }

        kernel_rules_buf = (kernel_rule_t *) mycalloc (kernel_rules_cnt, sizeof (kernel_rule_t));

        memset (kernel_rules_buf, 0, kernel_rules_cnt * sizeof (kernel_rule_t));

        for (uint i = 0; i < kernel_rules_cnt; i++)
        {
          uint out_pos = 0;

          kernel_rule_t *out = &kernel_rules_buf[i];

          for (uint j = 0; j < rp_files_cnt; j++)
          {
            uint in_off = (i / repeats[j]) % all_kernel_rules_cnt[j];
            uint in_pos;

            kernel_rule_t *in = &all_kernel_rules_buf[j][in_off];

            for (in_pos = 0; in->cmds[in_pos]; in_pos++, out_pos++)
            {
              if (out_pos == RULES_MAX - 1)
              {
                // log_info ("WARNING: Truncating chaining of rule %d and rule %d as maximum number of function calls per rule exceeded", i, in_off);

                break;
              }

              out->cmds[out_pos] = in->cmds[in_pos];
            }
          }
        }

        local_free (repeats);
      }
      else if (rp_gen)
      {
        uint kernel_rules_avail = 0;

        while (kernel_rules_cnt < rp_gen)
        {
          if (kernel_rules_avail == kernel_rules_cnt)
          {
            kernel_rules_buf = (kernel_rule_t *) myrealloc (kernel_rules_buf, kernel_rules_avail * sizeof (kernel_rule_t), INCR_RULES * sizeof (kernel_rule_t));

            kernel_rules_avail += INCR_RULES;
          }

          memset (rule_buf, 0, HCBUFSIZ_LARGE);

          rule_len = (int) generate_random_rule (rule_buf, rp_gen_func_min, rp_gen_func_max);

          if (cpu_rule_to_kernel_rule (rule_buf, rule_len, &kernel_rules_buf[kernel_rules_cnt]) == -1) continue;

          kernel_rules_cnt++;
        }
      }
    }

    myfree (rule_buf);

    /**
     * generate NOP rules
     */

    if ((rp_files_cnt == 0) && (rp_gen == 0))
    {
      kernel_rules_buf = (kernel_rule_t *) mymalloc (sizeof (kernel_rule_t));

      kernel_rules_buf[kernel_rules_cnt].cmds[0] = RULE_OP_MANGLE_NOOP;

      kernel_rules_cnt++;
    }

    data.kernel_rules_cnt = kernel_rules_cnt;
    data.kernel_rules_buf = kernel_rules_buf;

    if (kernel_rules_cnt == 0)
    {
      log_error ("ERROR: No valid rules left");

      return -1;
    }

    /**
     * OpenCL platforms: detect
     */

    cl_platform_id platforms[CL_PLATFORMS_MAX] = { 0 };
    cl_device_id platform_devices[DEVICES_MAX] = { 0 };

    cl_uint platforms_cnt = 0;
    cl_uint platform_devices_cnt = 0;

    if (keyspace == 0)
    {
      cl_int CL_err = hc_clGetPlatformIDs (data.ocl, CL_PLATFORMS_MAX, platforms, &platforms_cnt);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetPlatformIDs(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (platforms_cnt == 0)
      {
        log_info ("");
        log_info ("ATTENTION! No OpenCL compatible platform found");
        log_info ("");
        log_info ("You're probably missing the OpenCL runtime installation");
        log_info ("  AMD users require AMD drivers 14.9 or later (recommended 15.12 or later)");
        log_info ("  Intel users require Intel OpenCL Runtime 14.2 or later (recommended 15.1 or later)");
        log_info ("  NVidia users require NVidia drivers 346.59 or later (recommended 361.x or later)");
        log_info ("");

        return -1;
      }

      if (opencl_platforms_filter != (uint) -1)
      {
        uint platform_cnt_mask = ~(((uint) -1 >> platforms_cnt) << platforms_cnt);

        if (opencl_platforms_filter > platform_cnt_mask)
        {
          log_error ("ERROR: The platform selected by the --opencl-platforms parameter is larger than the number of available platforms (%d)", platforms_cnt);

          return -1;
        }
      }
    }

    if (opencl_device_types == NULL)
    {
      /**
       * OpenCL device types:
       *   In case the user did not specify --opencl-device-types and the user runs hashcat in a system with only a CPU only he probably want to use that CPU.
       */

      cl_device_type device_types_all = 0;

      for (uint platform_id = 0; platform_id < platforms_cnt; platform_id++)
      {
        if ((opencl_platforms_filter & (1u << platform_id)) == 0) continue;

        cl_platform_id platform = platforms[platform_id];

        cl_int CL_err = hc_clGetDeviceIDs (data.ocl, platform, CL_DEVICE_TYPE_ALL, DEVICES_MAX, platform_devices, &platform_devices_cnt);

        if (CL_err != CL_SUCCESS)
        {
          //log_error ("ERROR: clGetDeviceIDs(): %s\n", val2cstr_cl (CL_err));

          //return -1;

          // Silently ignore at this point, it will be reused later and create a note for the user at that point

          continue;
        }

        for (uint platform_devices_id = 0; platform_devices_id < platform_devices_cnt; platform_devices_id++)
        {
          cl_device_id device = platform_devices[platform_devices_id];

          cl_device_type device_type;

          cl_int CL_err = hc_clGetDeviceInfo (data.ocl, device, CL_DEVICE_TYPE, sizeof (device_type), &device_type, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          device_types_all |= device_type;
        }
      }

      // In such a case, automatically enable CPU device type support, since it's disabled by default.

      if ((device_types_all & (CL_DEVICE_TYPE_GPU | CL_DEVICE_TYPE_ACCELERATOR)) == 0)
      {
        device_types_filter |= CL_DEVICE_TYPE_CPU;
      }

      // In another case, when the user uses --stdout, using CPU devices is much faster to setup
      // If we have a CPU device, force it to be used

      if (stdout_flag == 1)
      {
        if (device_types_all & CL_DEVICE_TYPE_CPU)
        {
          device_types_filter = CL_DEVICE_TYPE_CPU;
        }
      }
    }

    /**
     * OpenCL devices: simply push all devices from all platforms into the same device array
     */

    int need_adl     = 0;
    int need_nvml    = 0;
    #ifndef __APPLE__
    int need_nvapi   = 0;
    int need_xnvctrl = 0;
    #endif

    hc_device_param_t *devices_param = (hc_device_param_t *) mycalloc (DEVICES_MAX, sizeof (hc_device_param_t));

    data.devices_param = devices_param;

    uint devices_cnt = 0;

    uint devices_active = 0;

    for (uint platform_id = 0; platform_id < platforms_cnt; platform_id++)
    {
      cl_int CL_err = CL_SUCCESS;

      cl_platform_id platform = platforms[platform_id];

      char platform_vendor[HCBUFSIZ_TINY] = { 0 };

      CL_err = hc_clGetPlatformInfo (data.ocl, platform, CL_PLATFORM_VENDOR, sizeof (platform_vendor), platform_vendor, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetPlatformInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      // find our own platform vendor because pocl and mesa are pushing original vendor_id through opencl
      // this causes trouble with vendor id based macros
      // we'll assign generic to those without special optimization available

      cl_uint platform_vendor_id = 0;

      if (strcmp (platform_vendor, CL_VENDOR_AMD) == 0)
      {
        platform_vendor_id = VENDOR_ID_AMD;
      }
      else if (strcmp (platform_vendor, CL_VENDOR_AMD_USE_INTEL) == 0)
      {
        platform_vendor_id = VENDOR_ID_AMD_USE_INTEL;
      }
      else if (strcmp (platform_vendor, CL_VENDOR_APPLE) == 0)
      {
        platform_vendor_id = VENDOR_ID_APPLE;
      }
      else if (strcmp (platform_vendor, CL_VENDOR_INTEL_BEIGNET) == 0)
      {
        platform_vendor_id = VENDOR_ID_INTEL_BEIGNET;
      }
      else if (strcmp (platform_vendor, CL_VENDOR_INTEL_SDK) == 0)
      {
        platform_vendor_id = VENDOR_ID_INTEL_SDK;
      }
      else if (strcmp (platform_vendor, CL_VENDOR_MESA) == 0)
      {
        platform_vendor_id = VENDOR_ID_MESA;
      }
      else if (strcmp (platform_vendor, CL_VENDOR_NV) == 0)
      {
        platform_vendor_id = VENDOR_ID_NV;
      }
      else if (strcmp (platform_vendor, CL_VENDOR_POCL) == 0)
      {
        platform_vendor_id = VENDOR_ID_POCL;
      }
      else
      {
        platform_vendor_id = VENDOR_ID_GENERIC;
      }

      uint platform_skipped = ((opencl_platforms_filter & (1u << platform_id)) == 0);

      CL_err = hc_clGetDeviceIDs (data.ocl, platform, CL_DEVICE_TYPE_ALL, DEVICES_MAX, platform_devices, &platform_devices_cnt);

      if (CL_err != CL_SUCCESS)
      {
        //log_error ("ERROR: clGetDeviceIDs(): %s\n", val2cstr_cl (CL_err));

        //return -1;

        platform_skipped = 2;
      }

      if ((benchmark == 1 || quiet == 0) && (algorithm_pos == 0))
      {
        if (machine_readable == 0)
        {
          if (platform_skipped == 0)
          {
            const int len = log_info ("OpenCL Platform #%u: %s", platform_id + 1, platform_vendor);

            char line[256] = { 0 };

            for (int i = 0; i < len; i++) line[i] = '=';

            log_info (line);
          }
          else if (platform_skipped == 1)
          {
            log_info ("OpenCL Platform #%u: %s, skipped", platform_id + 1, platform_vendor);
            log_info ("");
          }
          else if (platform_skipped == 2)
          {
            log_info ("OpenCL Platform #%u: %s, skipped! No OpenCL compatible devices found", platform_id + 1, platform_vendor);
            log_info ("");
          }
        }
      }

      if (platform_skipped == 1) continue;
      if (platform_skipped == 2) continue;

      for (uint platform_devices_id = 0; platform_devices_id < platform_devices_cnt; platform_devices_id++)
      {
        size_t param_value_size = 0;

        const uint device_id = devices_cnt;

        hc_device_param_t *device_param = &data.devices_param[device_id];

        device_param->platform_vendor_id = platform_vendor_id;

        device_param->device = platform_devices[platform_devices_id];

        device_param->device_id = device_id;

        device_param->platform_devices_id = platform_devices_id;

        device_param->platform = platform;

        // device_type

        cl_device_type device_type;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_TYPE, sizeof (device_type), &device_type, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_type &= ~CL_DEVICE_TYPE_DEFAULT;

        device_param->device_type = device_type;

        // device_name

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_NAME, 0, NULL, &param_value_size);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        char *device_name = (char *) mymalloc (param_value_size);

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_NAME, param_value_size, device_name, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->device_name = device_name;

        // device_vendor

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_VENDOR, 0, NULL, &param_value_size);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        char *device_vendor = (char *) mymalloc (param_value_size);

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_VENDOR, param_value_size, device_vendor, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->device_vendor = device_vendor;

        cl_uint device_vendor_id = 0;

        if (strcmp (device_vendor, CL_VENDOR_AMD) == 0)
        {
          device_vendor_id = VENDOR_ID_AMD;
        }
        else if (strcmp (device_vendor, CL_VENDOR_AMD_USE_INTEL) == 0)
        {
          device_vendor_id = VENDOR_ID_AMD_USE_INTEL;
        }
        else if (strcmp (device_vendor, CL_VENDOR_APPLE) == 0)
        {
          device_vendor_id = VENDOR_ID_APPLE;
        }
        else if (strcmp (device_vendor, CL_VENDOR_INTEL_BEIGNET) == 0)
        {
          device_vendor_id = VENDOR_ID_INTEL_BEIGNET;
        }
        else if (strcmp (device_vendor, CL_VENDOR_INTEL_SDK) == 0)
        {
          device_vendor_id = VENDOR_ID_INTEL_SDK;
        }
        else if (strcmp (device_vendor, CL_VENDOR_MESA) == 0)
        {
          device_vendor_id = VENDOR_ID_MESA;
        }
        else if (strcmp (device_vendor, CL_VENDOR_NV) == 0)
        {
          device_vendor_id = VENDOR_ID_NV;
        }
        else if (strcmp (device_vendor, CL_VENDOR_POCL) == 0)
        {
          device_vendor_id = VENDOR_ID_POCL;
        }
        else
        {
          device_vendor_id = VENDOR_ID_GENERIC;
        }

        device_param->device_vendor_id = device_vendor_id;

        // tuning db

        tuning_db_entry_t *tuningdb_entry = tuning_db_search (tuning_db, device_param, attack_mode, hashconfig->hash_mode);

        // device_version

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_VERSION, 0, NULL, &param_value_size);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        char *device_version = (char *) mymalloc (param_value_size);

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_VERSION, param_value_size, device_version, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->device_version = device_version;

        // device_opencl_version

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_OPENCL_C_VERSION, 0, NULL, &param_value_size);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        char *device_opencl_version = (char *) mymalloc (param_value_size);

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_OPENCL_C_VERSION, param_value_size, device_opencl_version, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->opencl_v12 = device_opencl_version[9] > '1' || device_opencl_version[11] >= '2';

        myfree (device_opencl_version);

        // vector_width

        cl_uint vector_width;

        if (opencl_vector_width_chgd == 0)
        {
          if (tuningdb_entry == NULL || tuningdb_entry->vector_width == -1)
          {
            if (hashconfig->opti_type & OPTI_TYPE_USES_BITS_64)
            {
              CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG, sizeof (vector_width), &vector_width, NULL);

              if (CL_err != CL_SUCCESS)
              {
                log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

                return -1;
              }
            }
            else
            {
              CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_NATIVE_VECTOR_WIDTH_INT,  sizeof (vector_width), &vector_width, NULL);

              if (CL_err != CL_SUCCESS)
              {
                log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

                return -1;
              }
            }
          }
          else
          {
            vector_width = (cl_uint) tuningdb_entry->vector_width;
          }
        }
        else
        {
          vector_width = opencl_vector_width;
        }

        if (vector_width > 16) vector_width = 16;

        device_param->vector_width = vector_width;

        // max_compute_units

        cl_uint device_processors;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof (device_processors), &device_processors, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->device_processors = device_processors;

        // device_maxmem_alloc
        // note we'll limit to 2gb, otherwise this causes all kinds of weird errors because of possible integer overflows in opencl runtimes

        cl_ulong device_maxmem_alloc;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof (device_maxmem_alloc), &device_maxmem_alloc, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->device_maxmem_alloc = MIN (device_maxmem_alloc, 0x7fffffff);

        // device_global_mem

        cl_ulong device_global_mem;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof (device_global_mem), &device_global_mem, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->device_global_mem = device_global_mem;

        // max_work_group_size

        size_t device_maxworkgroup_size;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof (device_maxworkgroup_size), &device_maxworkgroup_size, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->device_maxworkgroup_size = device_maxworkgroup_size;

        // max_clock_frequency

        cl_uint device_maxclock_frequency;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof (device_maxclock_frequency), &device_maxclock_frequency, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->device_maxclock_frequency = device_maxclock_frequency;

        // device_endian_little

        cl_bool device_endian_little;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_ENDIAN_LITTLE, sizeof (device_endian_little), &device_endian_little, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        if (device_endian_little == CL_FALSE)
        {
          log_info ("- Device #%u: WARNING: Not a little endian device", device_id + 1);

          device_param->skipped = 1;
        }

        // device_available

        cl_bool device_available;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_AVAILABLE, sizeof (device_available), &device_available, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        if (device_available == CL_FALSE)
        {
          log_info ("- Device #%u: WARNING: Device not available", device_id + 1);

          device_param->skipped = 1;
        }

        // device_compiler_available

        cl_bool device_compiler_available;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_COMPILER_AVAILABLE, sizeof (device_compiler_available), &device_compiler_available, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        if (device_compiler_available == CL_FALSE)
        {
          log_info ("- Device #%u: WARNING: No compiler available for device", device_id + 1);

          device_param->skipped = 1;
        }

        // device_execution_capabilities

        cl_device_exec_capabilities device_execution_capabilities;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_EXECUTION_CAPABILITIES, sizeof (device_execution_capabilities), &device_execution_capabilities, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        if ((device_execution_capabilities & CL_EXEC_KERNEL) == 0)
        {
          log_info ("- Device #%u: WARNING: Device does not support executing kernels", device_id + 1);

          device_param->skipped = 1;
        }

        // device_extensions

        size_t device_extensions_size;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_EXTENSIONS, 0, NULL, &device_extensions_size);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        char *device_extensions = mymalloc (device_extensions_size + 1);

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_EXTENSIONS, device_extensions_size, device_extensions, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        if (strstr (device_extensions, "base_atomics") == 0)
        {
          log_info ("- Device #%u: WARNING: Device does not support base atomics", device_id + 1);

          device_param->skipped = 1;
        }

        if (strstr (device_extensions, "byte_addressable_store") == 0)
        {
          log_info ("- Device #%u: WARNING: Device does not support byte addressable store", device_id + 1);

          device_param->skipped = 1;
        }

        myfree (device_extensions);

        // device_local_mem_size

        cl_ulong device_local_mem_size;

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_LOCAL_MEM_SIZE, sizeof (device_local_mem_size), &device_local_mem_size, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        if (device_local_mem_size < 32768)
        {
          log_info ("- Device #%u: WARNING: Device local mem size is too small", device_id + 1);

          device_param->skipped = 1;
        }

        // If there's both an Intel CPU and an AMD OpenCL runtime it's a tricky situation
        // Both platforms support CPU device types and therefore both will try to use 100% of the physical resources
        // This results in both utilizing it for 50%
        // However, Intel has much better SIMD control over their own hardware
        // It makes sense to give them full control over their own hardware

        if (device_type & CL_DEVICE_TYPE_CPU)
        {
          if (device_param->device_vendor_id == VENDOR_ID_AMD_USE_INTEL)
          {
            if (data.force == 0)
            {
              if (algorithm_pos == 0)
              {
                log_info ("- Device #%u: WARNING: Not a native Intel OpenCL runtime, expect massive speed loss", device_id + 1);
                log_info ("             You can use --force to override this but do not post error reports if you do so");
              }

              device_param->skipped = 1;
            }
          }
        }

        // skipped

        device_param->skipped |= ((devices_filter      & (1u << device_id)) == 0);
        device_param->skipped |= ((device_types_filter & (device_type))    == 0);

        // driver_version

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DRIVER_VERSION, 0, NULL, &param_value_size);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        char *driver_version = (char *) mymalloc (param_value_size);

        CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DRIVER_VERSION, param_value_size, driver_version, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_param->driver_version = driver_version;

        // device_name_chksum

        char *device_name_chksum = (char *) mymalloc (HCBUFSIZ_TINY);

        #if defined (__x86_64__)
        snprintf (device_name_chksum, HCBUFSIZ_TINY - 1, "%u-%u-%u-%s-%s-%s-%u", 64, device_param->platform_vendor_id, device_param->vector_width, device_param->device_name, device_param->device_version, device_param->driver_version, COMPTIME);
        #else
        snprintf (device_name_chksum, HCBUFSIZ_TINY - 1, "%u-%u-%u-%s-%s-%s-%u", 32, device_param->platform_vendor_id, device_param->vector_width, device_param->device_name, device_param->device_version, device_param->driver_version, COMPTIME);
        #endif

        uint device_name_digest[4] = { 0 };

        md5_64 ((uint *) device_name_chksum, device_name_digest);

        snprintf (device_name_chksum, HCBUFSIZ_TINY - 1, "%08x", device_name_digest[0]);

        device_param->device_name_chksum = device_name_chksum;

        // vendor specific

        if (device_param->device_type & CL_DEVICE_TYPE_GPU)
        {
          if ((device_param->platform_vendor_id == VENDOR_ID_AMD) && (device_param->device_vendor_id == VENDOR_ID_AMD))
          {
            need_adl = 1;
          }

          if ((device_param->platform_vendor_id == VENDOR_ID_NV) && (device_param->device_vendor_id == VENDOR_ID_NV))
          {
            need_nvml = 1;

            #if defined (__linux__)
            need_xnvctrl = 1;
            #endif

            #if defined (_WIN)
            need_nvapi = 1;
            #endif
          }
        }

        if (device_type & CL_DEVICE_TYPE_GPU)
        {
          if (device_vendor_id == VENDOR_ID_NV)
          {
            cl_uint kernel_exec_timeout = 0;

            #define CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV            0x4005

            CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV, sizeof (kernel_exec_timeout), &kernel_exec_timeout, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            device_param->kernel_exec_timeout = kernel_exec_timeout;

            cl_uint sm_minor = 0;
            cl_uint sm_major = 0;

            #define CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV       0x4000
            #define CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV       0x4001

            CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV, sizeof (sm_minor), &sm_minor, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            CL_err = hc_clGetDeviceInfo (data.ocl, device_param->device, CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof (sm_major), &sm_major, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            device_param->sm_minor = sm_minor;
            device_param->sm_major = sm_major;

            // CPU burning loop damper
            // Value is given as number between 0-100
            // By default 100%

            device_param->nvidia_spin_damp = (double) nvidia_spin_damp;

            if (nvidia_spin_damp_chgd == 0)
            {
              if (data.attack_mode == ATTACK_MODE_STRAIGHT)
              {
                /**
                 * the workaround is not a friend of rule based attacks
                 * the words from the wordlist combined with fast and slow rules cause
                 * fluctuations which cause inaccurate wait time estimations
                 * using a reduced damping percentage almost compensates this
                 */

                device_param->nvidia_spin_damp = 64;
              }
            }

            device_param->nvidia_spin_damp /= 100;
          }
        }

        // display results

        if ((benchmark == 1 || quiet == 0) && (algorithm_pos == 0))
        {
          if (machine_readable == 0)
          {
            if (device_param->skipped == 0)
            {
              log_info ("- Device #%u: %s, %lu/%lu MB allocatable, %uMCU",
                        device_id + 1,
                        device_name,
                        (unsigned int) (device_maxmem_alloc / 1024 / 1024),
                        (unsigned int) (device_global_mem   / 1024 / 1024),
                        (unsigned int)  device_processors);
            }
            else
            {
              log_info ("- Device #%u: %s, skipped",
                        device_id + 1,
                        device_name);
            }
          }
        }

        // common driver check

        if (device_param->skipped == 0)
        {
          if (device_type & CL_DEVICE_TYPE_GPU)
          {
            if (platform_vendor_id == VENDOR_ID_AMD)
            {
              int catalyst_check = (force == 1) ? 0 : 1;

              int catalyst_warn = 0;

              int catalyst_broken = 0;

              if (catalyst_check == 1)
              {
                catalyst_warn = 1;

                // v14.9 and higher
                if (atoi (device_param->driver_version) >= 1573)
                {
                  catalyst_warn = 0;
                }

                catalyst_check = 0;
              }

              if (catalyst_broken == 1)
              {
                log_info ("");
                log_info ("ATTENTION! The Catalyst driver installed on your system is known to be broken!");
                log_info ("It passes over cracked hashes and will not report them as cracked");
                log_info ("You are STRONGLY encouraged not to use it");
                log_info ("You can use --force to override this but do not post error reports if you do so");
                log_info ("");

                return -1;
              }

              if (catalyst_warn == 1)
              {
                log_info ("");
                log_info ("ATTENTION! Unsupported or incorrectly installed Catalyst driver detected!");
                log_info ("You are STRONGLY encouraged to use the official supported catalyst driver");
                log_info ("See hashcat's homepage for official supported catalyst drivers");
                #if defined (_WIN)
                log_info ("Also see: http://hashcat.net/wiki/doku.php?id=upgrading_amd_drivers_how_to");
                #endif
                log_info ("You can use --force to override this but do not post error reports if you do so");
                log_info ("");

                return -1;
              }
            }
            else if (platform_vendor_id == VENDOR_ID_NV)
            {
              if (device_param->kernel_exec_timeout != 0)
              {
                if (data.quiet == 0) log_info ("- Device #%u: WARNING! Kernel exec timeout is not disabled, it might cause you errors of code 702", device_id + 1);
                if (data.quiet == 0) log_info ("             See the wiki on how to disable it: https://hashcat.net/wiki/doku.php?id=timeout_patch");
              }
            }
          }

          /* turns out pocl still creates segfaults (because of llvm)
          if (device_type & CL_DEVICE_TYPE_CPU)
          {
            if (platform_vendor_id == VENDOR_ID_AMD)
            {
              if (force == 0)
              {
                log_info ("");
                log_info ("ATTENTION! OpenCL support for CPU of catalyst driver is not reliable.");
                log_info ("You are STRONGLY encouraged not to use it");
                log_info ("You can use --force to override this but do not post error reports if you do so");
                log_info ("A good alternative is the free pocl >= v0.13, but make sure to use a LLVM >= v3.8");
                log_info ("");

                return -1;
              }
            }
          }
          */

          /**
           * kernel accel and loops tuning db adjustment
           */

          device_param->kernel_accel_min = 1;
          device_param->kernel_accel_max = 1024;

          device_param->kernel_loops_min = 1;
          device_param->kernel_loops_max = 1024;

          tuning_db_entry_t *tuningdb_entry = tuning_db_search (tuning_db, device_param, attack_mode, hashconfig->hash_mode);

          if (tuningdb_entry)
          {
            u32 _kernel_accel = tuningdb_entry->kernel_accel;
            u32 _kernel_loops = tuningdb_entry->kernel_loops;

            if (_kernel_accel)
            {
              device_param->kernel_accel_min = _kernel_accel;
              device_param->kernel_accel_max = _kernel_accel;
            }

            if (_kernel_loops)
            {
              if (workload_profile == 1)
              {
                _kernel_loops = (_kernel_loops > 8) ? _kernel_loops / 8 : 1;
              }
              else if (workload_profile == 2)
              {
                _kernel_loops = (_kernel_loops > 4) ? _kernel_loops / 4 : 1;
              }

              device_param->kernel_loops_min = _kernel_loops;
              device_param->kernel_loops_max = _kernel_loops;
            }
          }

          // commandline parameters overwrite tuningdb entries

          if (kernel_accel)
          {
            device_param->kernel_accel_min = kernel_accel;
            device_param->kernel_accel_max = kernel_accel;
          }

          if (kernel_loops)
          {
            device_param->kernel_loops_min = kernel_loops;
            device_param->kernel_loops_max = kernel_loops;
          }

          /**
           * activate device
           */

          devices_active++;
        }

        // next please

        devices_cnt++;
      }

      if ((benchmark == 1 || quiet == 0) && (algorithm_pos == 0))
      {
        if (machine_readable == 0)
        {
          log_info ("");
        }
      }
    }

    if (keyspace == 0 && devices_active == 0)
    {
      log_error ("ERROR: No devices found/left");

      return -1;
    }

    // additional check to see if the user has chosen a device that is not within the range of available devices (i.e. larger than devices_cnt)

    if (devices_filter != (uint) -1)
    {
      uint devices_cnt_mask = ~(((uint) -1 >> devices_cnt) << devices_cnt);

      if (devices_filter > devices_cnt_mask)
      {
        log_error ("ERROR: The device specified by the --opencl-devices parameter is larger than the number of available devices (%d)", devices_cnt);

        return -1;
      }
    }

    data.devices_cnt = devices_cnt;

    data.devices_active = devices_active;

    /**
     * HM devices: init
     */

    #if defined (HAVE_HWMON)
    hm_attrs_t hm_adapters_adl[DEVICES_MAX];
    hm_attrs_t hm_adapters_nvapi[DEVICES_MAX];
    hm_attrs_t hm_adapters_nvml[DEVICES_MAX];
    hm_attrs_t hm_adapters_xnvctrl[DEVICES_MAX];

    memset (hm_adapters_adl,     0, sizeof (hm_adapters_adl));
    memset (hm_adapters_nvapi,   0, sizeof (hm_adapters_nvapi));
    memset (hm_adapters_nvml,    0, sizeof (hm_adapters_nvml));
    memset (hm_adapters_xnvctrl, 0, sizeof (hm_adapters_xnvctrl));

    if (gpu_temp_disable == 0)
    {
      ADL_PTR     *adl     = (ADL_PTR *)     mymalloc (sizeof (ADL_PTR));
      NVAPI_PTR   *nvapi   = (NVAPI_PTR *)   mymalloc (sizeof (NVAPI_PTR));
      NVML_PTR    *nvml    = (NVML_PTR *)    mymalloc (sizeof (NVML_PTR));
      XNVCTRL_PTR *xnvctrl = (XNVCTRL_PTR *) mymalloc (sizeof (XNVCTRL_PTR));

      data.hm_adl     = NULL;
      data.hm_nvapi   = NULL;
      data.hm_nvml    = NULL;
      data.hm_xnvctrl = NULL;

      if ((need_nvml == 1) && (nvml_init (nvml) == 0))
      {
        data.hm_nvml = nvml;
      }

      if (data.hm_nvml)
      {
        if (hm_NVML_nvmlInit (data.hm_nvml) == NVML_SUCCESS)
        {
          HM_ADAPTER_NVML nvmlGPUHandle[DEVICES_MAX] = { 0 };

          int tmp_in = hm_get_adapter_index_nvml (nvmlGPUHandle);

          int tmp_out = 0;

          for (int i = 0; i < tmp_in; i++)
          {
            hm_adapters_nvml[tmp_out++].nvml = nvmlGPUHandle[i];
          }

          for (int i = 0; i < tmp_out; i++)
          {
            unsigned int speed;

            if (hm_NVML_nvmlDeviceGetFanSpeed (data.hm_nvml, 0, hm_adapters_nvml[i].nvml, &speed) == NVML_SUCCESS) hm_adapters_nvml[i].fan_get_supported = 1;

            // doesn't seem to create any advantages
            //hm_NVML_nvmlDeviceSetComputeMode (data.hm_nvml, 1, hm_adapters_nvml[i].nvml, NVML_COMPUTEMODE_EXCLUSIVE_PROCESS);
            //hm_NVML_nvmlDeviceSetGpuOperationMode (data.hm_nvml, 1, hm_adapters_nvml[i].nvml, NVML_GOM_ALL_ON);
          }
        }
      }

      if ((need_nvapi == 1) && (nvapi_init (nvapi) == 0))
      {
        data.hm_nvapi = nvapi;
      }

      if (data.hm_nvapi)
      {
        if (hm_NvAPI_Initialize (data.hm_nvapi) == NVAPI_OK)
        {
          HM_ADAPTER_NVAPI nvGPUHandle[DEVICES_MAX] = { 0 };

          int tmp_in = hm_get_adapter_index_nvapi (nvGPUHandle);

          int tmp_out = 0;

          for (int i = 0; i < tmp_in; i++)
          {
            hm_adapters_nvapi[tmp_out++].nvapi = nvGPUHandle[i];
          }
        }
      }

      if ((need_xnvctrl == 1) && (xnvctrl_init (xnvctrl) == 0))
      {
        data.hm_xnvctrl = xnvctrl;
      }

      if (data.hm_xnvctrl)
      {
        if (hm_XNVCTRL_XOpenDisplay (data.hm_xnvctrl) == 0)
        {
          for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
          {
            hc_device_param_t *device_param = &data.devices_param[device_id];

            if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

            hm_adapters_xnvctrl[device_id].xnvctrl = device_id;

            int speed = 0;

            if (get_fan_speed_current (data.hm_xnvctrl, device_id, &speed) == 0) hm_adapters_xnvctrl[device_id].fan_get_supported = 1;
          }
        }
      }

      if ((need_adl == 1) && (adl_init (adl) == 0))
      {
        data.hm_adl = adl;
      }

      if (data.hm_adl)
      {
        if (hm_ADL_Main_Control_Create (data.hm_adl, ADL_Main_Memory_Alloc, 0) == ADL_OK)
        {
          // total number of adapters

          int hm_adapters_num;

          if (get_adapters_num_adl (data.hm_adl, &hm_adapters_num) != 0) return -1;

          // adapter info

          LPAdapterInfo lpAdapterInfo = hm_get_adapter_info_adl (data.hm_adl, hm_adapters_num);

          if (lpAdapterInfo == NULL) return -1;

          // get a list (of ids of) valid/usable adapters

          int num_adl_adapters = 0;

          u32 *valid_adl_device_list = hm_get_list_valid_adl_adapters (hm_adapters_num, &num_adl_adapters, lpAdapterInfo);

          if (num_adl_adapters > 0)
          {
            hc_thread_mutex_lock (mux_hwmon);

            // hm_get_opencl_busid_devid (hm_adapters_adl, devices_all_cnt, devices_all);

            hm_get_adapter_index_adl (hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);

            hm_get_overdrive_version  (data.hm_adl, hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);
            hm_check_fanspeed_control (data.hm_adl, hm_adapters_adl, valid_adl_device_list, num_adl_adapters, lpAdapterInfo);

            hc_thread_mutex_unlock (mux_hwmon);
          }

          myfree (valid_adl_device_list);
          myfree (lpAdapterInfo);
        }
      }

      if (data.hm_adl == NULL && data.hm_nvml == NULL && data.hm_xnvctrl == NULL)
      {
        gpu_temp_disable = 1;
      }
    }

    /**
     * OpenCL devices: allocate buffer for device specific information
     */

    ADLOD6MemClockState *od_clock_mem_status = (ADLOD6MemClockState *) mycalloc (data.devices_cnt, sizeof (ADLOD6MemClockState));

    int *od_power_control_status = (int *) mycalloc (data.devices_cnt, sizeof (int));

    unsigned int *nvml_power_limit = (unsigned int *) mycalloc (data.devices_cnt, sizeof (unsigned int));

    /**
     * User-defined GPU temp handling
     */

    if (gpu_temp_disable == 1)
    {
      gpu_temp_abort  = 0;
      gpu_temp_retain = 0;
    }

    if ((gpu_temp_abort != 0) && (gpu_temp_retain != 0))
    {
      if (gpu_temp_abort < gpu_temp_retain)
      {
        log_error ("ERROR: Invalid values for gpu-temp-abort. Parameter gpu-temp-abort is less than gpu-temp-retain.");

        return -1;
      }
    }

    data.gpu_temp_disable = gpu_temp_disable;
    data.gpu_temp_abort   = gpu_temp_abort;
    data.gpu_temp_retain  = gpu_temp_retain;
    #endif

    /**
     * enable custom signal handler(s)
     */

    if (benchmark == 0)
    {
      hc_signal (sigHandler_default);
    }
    else
    {
      hc_signal (sigHandler_benchmark);
    }

    /**
     * inform the user
     */

    if (data.quiet == 0)
    {
      log_info ("Hashes: %u hashes; %u unique digests, %u unique salts", hashes_cnt_orig, digests_cnt, salts_cnt);

      log_info ("Bitmaps: %u bits, %u entries, 0x%08x mask, %u bytes, %u/%u rotates", bitmap_bits, bitmap_nums, bitmap_mask, bitmap_size, bitmap_shift1, bitmap_shift2);

      if (attack_mode == ATTACK_MODE_STRAIGHT)
      {
        log_info ("Rules: %u", kernel_rules_cnt);
      }

      if (hashconfig->opti_type)
      {
        log_info ("Applicable Optimizers:");

        for (uint i = 0; i < 32; i++)
        {
          const uint opti_bit = 1u << i;

          if (hashconfig->opti_type & opti_bit) log_info ("* %s", stroptitype (opti_bit));
        }
      }

      /**
       * Watchdog and Temperature balance
       */

      #if defined (HAVE_HWMON)
      if (gpu_temp_disable == 0 && data.hm_adl == NULL && data.hm_nvml == NULL && data.hm_xnvctrl == NULL)
      {
        log_info ("Watchdog: Hardware Monitoring Interface not found on your system");
      }

      if (gpu_temp_abort == 0)
      {
        log_info ("Watchdog: Temperature abort trigger disabled");
      }
      else
      {
        log_info ("Watchdog: Temperature abort trigger set to %uc", gpu_temp_abort);
      }

      if (gpu_temp_retain == 0)
      {
        log_info ("Watchdog: Temperature retain trigger disabled");
      }
      else
      {
        log_info ("Watchdog: Temperature retain trigger set to %uc", gpu_temp_retain);
      }

      if (data.quiet == 0) log_info ("");
      #endif
    }

    #if defined (HAVE_HWMON)

    /**
     * HM devices: copy
     */

    if (gpu_temp_disable == 0)
    {
      for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &data.devices_param[device_id];

        if ((device_param->device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        if (device_param->skipped) continue;

        const uint platform_devices_id = device_param->platform_devices_id;

        if (device_param->device_vendor_id == VENDOR_ID_AMD)
        {
          data.hm_device[device_id].adl               = hm_adapters_adl[platform_devices_id].adl;
          data.hm_device[device_id].nvapi             = 0;
          data.hm_device[device_id].nvml              = 0;
          data.hm_device[device_id].xnvctrl           = 0;
          data.hm_device[device_id].od_version        = hm_adapters_adl[platform_devices_id].od_version;
          data.hm_device[device_id].fan_get_supported = hm_adapters_adl[platform_devices_id].fan_get_supported;
          data.hm_device[device_id].fan_set_supported = 0;
        }

        if (device_param->device_vendor_id == VENDOR_ID_NV)
        {
          data.hm_device[device_id].adl               = 0;
          data.hm_device[device_id].nvapi             = hm_adapters_nvapi[platform_devices_id].nvapi;
          data.hm_device[device_id].nvml              = hm_adapters_nvml[platform_devices_id].nvml;
          data.hm_device[device_id].xnvctrl           = hm_adapters_xnvctrl[platform_devices_id].xnvctrl;
          data.hm_device[device_id].od_version        = 0;
          data.hm_device[device_id].fan_get_supported = hm_adapters_nvml[platform_devices_id].fan_get_supported;
          data.hm_device[device_id].fan_set_supported = 0;
        }
      }
    }

    /**
     * powertune on user request
     */

    if (powertune_enable == 1)
    {
      hc_thread_mutex_lock (mux_hwmon);

      for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &data.devices_param[device_id];

        if (device_param->skipped) continue;

        if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
        {
          /**
           * Temporary fix:
           * with AMD r9 295x cards it seems that we need to set the powertune value just AFTER the ocl init stuff
           * otherwise after hc_clCreateContext () etc, powertune value was set back to "normal" and cards unfortunately
           * were not working @ full speed (setting hm_ADL_Overdrive_PowerControl_Set () here seems to fix the problem)
           * Driver / ADL bug?
           */

          if (data.hm_device[device_id].od_version == 6)
          {
            int ADL_rc;

            // check powertune capabilities first, if not available then skip device

            int powertune_supported = 0;

            if ((ADL_rc = hm_ADL_Overdrive6_PowerControl_Caps (data.hm_adl, data.hm_device[device_id].adl, &powertune_supported)) != ADL_OK)
            {
              log_error ("ERROR: Failed to get ADL PowerControl Capabilities");

              return -1;
            }

            // first backup current value, we will restore it later

            if (powertune_supported != 0)
            {
              // powercontrol settings

              ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

              if ((ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (data.hm_adl, data.hm_device[device_id].adl, &powertune)) == ADL_OK)
              {
                ADL_rc = hm_ADL_Overdrive_PowerControl_Get (data.hm_adl, data.hm_device[device_id].adl, &od_power_control_status[device_id]);
              }

              if (ADL_rc != ADL_OK)
              {
                log_error ("ERROR: Failed to get current ADL PowerControl settings");

                return -1;
              }

              if ((ADL_rc = hm_ADL_Overdrive_PowerControl_Set (data.hm_adl, data.hm_device[device_id].adl, powertune.iMaxValue)) != ADL_OK)
              {
                log_error ("ERROR: Failed to set new ADL PowerControl values");

                return -1;
              }

              // clocks

              memset (&od_clock_mem_status[device_id], 0, sizeof (ADLOD6MemClockState));

              od_clock_mem_status[device_id].state.iNumberOfPerformanceLevels = 2;

              if ((ADL_rc = hm_ADL_Overdrive_StateInfo_Get (data.hm_adl, data.hm_device[device_id].adl, ADL_OD6_GETSTATEINFO_CUSTOM_PERFORMANCE, &od_clock_mem_status[device_id])) != ADL_OK)
              {
                log_error ("ERROR: Failed to get ADL memory and engine clock frequency");

                return -1;
              }

              // Query capabilities only to see if profiles were not "damaged", if so output a warning but do accept the users profile settings

              ADLOD6Capabilities caps = {0, 0, 0, {0, 0, 0}, {0, 0, 0}, 0, 0};

              if ((ADL_rc = hm_ADL_Overdrive_Capabilities_Get (data.hm_adl, data.hm_device[device_id].adl, &caps)) != ADL_OK)
              {
                log_error ("ERROR: Failed to get ADL device capabilities");

                return -1;
              }

              int engine_clock_max =       (int) (0.6666 * caps.sEngineClockRange.iMax);
              int memory_clock_max =       (int) (0.6250 * caps.sMemoryClockRange.iMax);

              int warning_trigger_engine = (int) (0.25   * engine_clock_max);
              int warning_trigger_memory = (int) (0.25   * memory_clock_max);

              int engine_clock_profile_max = od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
              int memory_clock_profile_max = od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

              // warning if profile has too low max values

              if ((engine_clock_max - engine_clock_profile_max) > warning_trigger_engine)
              {
                log_info ("WARN: The custom profile seems to have too low maximum engine clock values. You therefore may not reach full performance");
              }

              if ((memory_clock_max - memory_clock_profile_max) > warning_trigger_memory)
              {
                log_info ("WARN: The custom profile seems to have too low maximum memory clock values. You therefore may not reach full performance");
              }

              ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) mycalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

              performance_state->iNumberOfPerformanceLevels = 2;

              performance_state->aLevels[0].iEngineClock = engine_clock_profile_max;
              performance_state->aLevels[1].iEngineClock = engine_clock_profile_max;
              performance_state->aLevels[0].iMemoryClock = memory_clock_profile_max;
              performance_state->aLevels[1].iMemoryClock = memory_clock_profile_max;

              if ((ADL_rc = hm_ADL_Overdrive_State_Set (data.hm_adl, data.hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state)) != ADL_OK)
              {
                log_info ("ERROR: Failed to set ADL performance state");

                return -1;
              }

              local_free (performance_state);
            }

            // set powertune value only

            if (powertune_supported != 0)
            {
              // powertune set
              ADLOD6PowerControlInfo powertune = {0, 0, 0, 0, 0};

              if ((ADL_rc = hm_ADL_Overdrive_PowerControlInfo_Get (data.hm_adl, data.hm_device[device_id].adl, &powertune)) != ADL_OK)
              {
                log_error ("ERROR: Failed to get current ADL PowerControl settings");

                return -1;
              }

              if ((ADL_rc = hm_ADL_Overdrive_PowerControl_Set (data.hm_adl, data.hm_device[device_id].adl, powertune.iMaxValue)) != ADL_OK)
              {
                log_error ("ERROR: Failed to set new ADL PowerControl values");

                return -1;
              }
            }
          }
        }

        if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
        {
          // first backup current value, we will restore it later

          unsigned int limit;

          int powertune_supported = 0;

          if (hm_NVML_nvmlDeviceGetPowerManagementLimit (data.hm_nvml, 0, data.hm_device[device_id].nvml, &limit) == NVML_SUCCESS)
          {
            powertune_supported = 1;
          }

          // if backup worked, activate the maximum allowed

          if (powertune_supported != 0)
          {
            unsigned int minLimit;
            unsigned int maxLimit;

            if (hm_NVML_nvmlDeviceGetPowerManagementLimitConstraints (data.hm_nvml, 0, data.hm_device[device_id].nvml, &minLimit, &maxLimit) == NVML_SUCCESS)
            {
              if (maxLimit > 0)
              {
                if (hm_NVML_nvmlDeviceSetPowerManagementLimit (data.hm_nvml, 0, data.hm_device[device_id].nvml, maxLimit) == NVML_SUCCESS)
                {
                  // now we can be sure we need to reset later

                  nvml_power_limit[device_id] = limit;
                }
              }
            }
          }
        }
      }

      hc_thread_mutex_unlock (mux_hwmon);
    }

    #endif // HAVE_HWMON

    #if defined (DEBUG)
    if (benchmark == 1) log_info ("Hashmode: %d", hashconfig->hash_mode);
    #endif

    if (data.quiet == 0) log_info_nn ("Initializing device kernels and memory...");

    for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
    {
      cl_int CL_err = CL_SUCCESS;

      /**
       * host buffer
       */

      hc_device_param_t *device_param = &data.devices_param[device_id];

      if (device_param->skipped) continue;

      /**
       * device properties
       */

      const char *device_name_chksum      = device_param->device_name_chksum;
      const u32   device_processors       = device_param->device_processors;

      /**
       * create context for each device
       */

      cl_context_properties properties[3];

      properties[0] = CL_CONTEXT_PLATFORM;
      properties[1] = (cl_context_properties) device_param->platform;
      properties[2] = 0;

      CL_err = hc_clCreateContext (data.ocl, properties, 1, &device_param->device, NULL, NULL, &device_param->context);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clCreateContext(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      /**
       * create command-queue
       */

      // not supported with NV
      // device_param->command_queue = hc_clCreateCommandQueueWithProperties (device_param->context, device_param->device, NULL);

      CL_err = hc_clCreateCommandQueue (data.ocl, device_param->context, device_param->device, CL_QUEUE_PROFILING_ENABLE, &device_param->command_queue);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clCreateCommandQueue(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      /**
       * kernel threads: some algorithms need a fixed kernel-threads count
       *                 because of shared memory usage or bitslice
       *                 there needs to be some upper limit, otherwise there's too much overhead
       */

      uint kernel_threads = MIN (KERNEL_THREADS_MAX, device_param->device_maxworkgroup_size);

      if (hashconfig->hash_mode ==  8900) kernel_threads = 64; // Scrypt
      if (hashconfig->hash_mode ==  9300) kernel_threads = 64; // Scrypt

      if (device_param->device_type & CL_DEVICE_TYPE_CPU)
      {
        kernel_threads = KERNEL_THREADS_MAX_CPU;
      }

      if (hashconfig->hash_mode ==  1500) kernel_threads = 64; // DES
      if (hashconfig->hash_mode ==  3000) kernel_threads = 64; // DES
      if (hashconfig->hash_mode ==  3100) kernel_threads = 64; // DES
      if (hashconfig->hash_mode ==  3200) kernel_threads = 8;  // Blowfish
      if (hashconfig->hash_mode ==  7500) kernel_threads = 64; // RC4
      if (hashconfig->hash_mode ==  8500) kernel_threads = 64; // DES
      if (hashconfig->hash_mode ==  9000) kernel_threads = 8;  // Blowfish
      if (hashconfig->hash_mode ==  9700) kernel_threads = 64; // RC4
      if (hashconfig->hash_mode ==  9710) kernel_threads = 64; // RC4
      if (hashconfig->hash_mode ==  9800) kernel_threads = 64; // RC4
      if (hashconfig->hash_mode ==  9810) kernel_threads = 64; // RC4
      if (hashconfig->hash_mode == 10400) kernel_threads = 64; // RC4
      if (hashconfig->hash_mode == 10410) kernel_threads = 64; // RC4
      if (hashconfig->hash_mode == 10500) kernel_threads = 64; // RC4
      if (hashconfig->hash_mode == 13100) kernel_threads = 64; // RC4
      if (hashconfig->hash_mode == 14000) kernel_threads = 64; // DES
      if (hashconfig->hash_mode == 14100) kernel_threads = 64; // DES

      device_param->kernel_threads = kernel_threads;

      device_param->hardware_power = device_processors * kernel_threads;

      /**
       * create input buffers on device : calculate size of fixed memory buffers
       */

      size_t size_root_css   = SP_PW_MAX *           sizeof (cs_t);
      size_t size_markov_css = SP_PW_MAX * CHARSIZ * sizeof (cs_t);

      device_param->size_root_css   = size_root_css;
      device_param->size_markov_css = size_markov_css;

      size_t size_results = sizeof (uint);

      device_param->size_results = size_results;

      size_t size_rules   = kernel_rules_cnt * sizeof (kernel_rule_t);
      size_t size_rules_c = KERNEL_RULES     * sizeof (kernel_rule_t);

      size_t size_plains  = digests_cnt * sizeof (plain_t);
      size_t size_salts   = salts_cnt   * sizeof (salt_t);
      size_t size_esalts  = salts_cnt   * hashconfig->esalt_size;

      device_param->size_plains   = size_plains;
      device_param->size_digests  = size_digests;
      device_param->size_shown    = size_shown;
      device_param->size_salts    = size_salts;

      size_t size_combs = KERNEL_COMBS * sizeof (comb_t);
      size_t size_bfs   = KERNEL_BFS   * sizeof (bf_t);
      size_t size_tm    = 32           * sizeof (bs_word_t);

      // scryptV stuff

      size_t size_scrypt = 4;

      if ((hashconfig->hash_mode == 8900) || (hashconfig->hash_mode == 9300))
      {
        // we need to check that all hashes have the same scrypt settings

        const u32 scrypt_N = data.salts_buf[0].scrypt_N;
        const u32 scrypt_r = data.salts_buf[0].scrypt_r;
        const u32 scrypt_p = data.salts_buf[0].scrypt_p;

        for (uint i = 1; i < salts_cnt; i++)
        {
          if ((data.salts_buf[i].scrypt_N != scrypt_N)
           || (data.salts_buf[i].scrypt_r != scrypt_r)
           || (data.salts_buf[i].scrypt_p != scrypt_p))
          {
            log_error ("ERROR: Mixed scrypt settings not supported");

            return -1;
          }
        }

        uint tmto_start = 0;
        uint tmto_stop  = 10;

        if (scrypt_tmto)
        {
          tmto_start = scrypt_tmto;
        }
        else
        {
          // in case the user did not specify the tmto manually
          // use some values known to run best (tested on 290x for AMD and GTX1080 for NV)

          if (hashconfig->hash_mode == 8900)
          {
            if (device_param->device_vendor_id == VENDOR_ID_AMD)
            {
              tmto_start = 3;
            }
            else if (device_param->device_vendor_id == VENDOR_ID_NV)
            {
              tmto_start = 2;
            }
          }
          else if (hashconfig->hash_mode == 9300)
          {
            if (device_param->device_vendor_id == VENDOR_ID_AMD)
            {
              tmto_start = 2;
            }
            else if (device_param->device_vendor_id == VENDOR_ID_NV)
            {
              tmto_start = 4;
            }
          }
        }

        data.scrypt_tmp_size = (128 * scrypt_r * scrypt_p);

        device_param->kernel_accel_min = 1;
        device_param->kernel_accel_max = 8;

        uint tmto;

        for (tmto = tmto_start; tmto < tmto_stop; tmto++)
        {
          size_scrypt = (128 * scrypt_r) * scrypt_N;

          size_scrypt /= 1u << tmto;

          size_scrypt *= device_param->device_processors * device_param->kernel_threads * device_param->kernel_accel_max;

          if ((size_scrypt / 4) > device_param->device_maxmem_alloc)
          {
            if (quiet == 0) log_info ("WARNING: Not enough single-block device memory allocatable to use --scrypt-tmto %d, increasing...", tmto);

            continue;
          }

          if (size_scrypt > device_param->device_global_mem)
          {
            if (quiet == 0) log_info ("WARNING: Not enough total device memory allocatable to use --scrypt-tmto %d, increasing...", tmto);

            continue;
          }

          for (uint salts_pos = 0; salts_pos < data.salts_cnt; salts_pos++)
          {
            data.scrypt_tmto_final = tmto;
          }

          break;
        }

        if (tmto == tmto_stop)
        {
          log_error ("ERROR: Can't allocate enough device memory");

          return -1;
        }

        if (quiet == 0) log_info ("SCRYPT tmto optimizer value set to: %u, mem: %" PRIu64 "\n", data.scrypt_tmto_final, size_scrypt);
      }

      size_t size_scrypt4 = size_scrypt / 4;

      /**
       * some algorithms need a fixed kernel-loops count
       */

      if (hashconfig->hash_mode == 1500 && attack_mode == ATTACK_MODE_BF)
      {
        const u32 kernel_loops_fixed = 1024;

        device_param->kernel_loops_min = kernel_loops_fixed;
        device_param->kernel_loops_max = kernel_loops_fixed;
      }

      if (hashconfig->hash_mode == 3000 && attack_mode == ATTACK_MODE_BF)
      {
        const u32 kernel_loops_fixed = 1024;

        device_param->kernel_loops_min = kernel_loops_fixed;
        device_param->kernel_loops_max = kernel_loops_fixed;
      }

      if (hashconfig->hash_mode == 8900)
      {
        const u32 kernel_loops_fixed = 1;

        device_param->kernel_loops_min = kernel_loops_fixed;
        device_param->kernel_loops_max = kernel_loops_fixed;
      }

      if (hashconfig->hash_mode == 9300)
      {
        const u32 kernel_loops_fixed = 1;

        device_param->kernel_loops_min = kernel_loops_fixed;
        device_param->kernel_loops_max = kernel_loops_fixed;
      }

      if (hashconfig->hash_mode == 12500)
      {
        const u32 kernel_loops_fixed = ROUNDS_RAR3 / 16;

        device_param->kernel_loops_min = kernel_loops_fixed;
        device_param->kernel_loops_max = kernel_loops_fixed;
      }

      if (hashconfig->hash_mode == 14000 && attack_mode == ATTACK_MODE_BF)
      {
        const u32 kernel_loops_fixed = 1024;

        device_param->kernel_loops_min = kernel_loops_fixed;
        device_param->kernel_loops_max = kernel_loops_fixed;
      }

      if (hashconfig->hash_mode == 14100 && attack_mode == ATTACK_MODE_BF)
      {
        const u32 kernel_loops_fixed = 1024;

        device_param->kernel_loops_min = kernel_loops_fixed;
        device_param->kernel_loops_max = kernel_loops_fixed;
      }

      /**
       * some algorithms have a maximum kernel-loops count
       */

      if (device_param->kernel_loops_min < device_param->kernel_loops_max)
      {
        u32 innerloop_cnt = 0;

        if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
        {
          if      (data.attack_kern == ATTACK_KERN_STRAIGHT)  innerloop_cnt = data.kernel_rules_cnt;
          else if (data.attack_kern == ATTACK_KERN_COMBI)     innerloop_cnt = data.combs_cnt;
          else if (data.attack_kern == ATTACK_KERN_BF)        innerloop_cnt = data.bfs_cnt;
        }
        else
        {
          innerloop_cnt = data.salts_buf[0].salt_iter;
        }

        if ((innerloop_cnt >= device_param->kernel_loops_min) &&
            (innerloop_cnt <= device_param->kernel_loops_max))
        {
          device_param->kernel_loops_max = innerloop_cnt;
        }
      }

      u32 kernel_accel_min = device_param->kernel_accel_min;
      u32 kernel_accel_max = device_param->kernel_accel_max;

      // find out if we would request too much memory on memory blocks which are based on kernel_accel

      size_t size_pws   = 4;
      size_t size_tmps  = 4;
      size_t size_hooks = 4;

      while (kernel_accel_max >= kernel_accel_min)
      {
        const u32 kernel_power_max = device_processors * kernel_threads * kernel_accel_max;

        // size_pws

        size_pws = kernel_power_max * sizeof (pw_t);

        // size_tmps

        switch (hashconfig->hash_mode)
        {
          case   400: size_tmps = kernel_power_max * sizeof (phpass_tmp_t);          break;
          case   500: size_tmps = kernel_power_max * sizeof (md5crypt_tmp_t);        break;
          case   501: size_tmps = kernel_power_max * sizeof (md5crypt_tmp_t);        break;
          case  1600: size_tmps = kernel_power_max * sizeof (md5crypt_tmp_t);        break;
          case  1800: size_tmps = kernel_power_max * sizeof (sha512crypt_tmp_t);     break;
          case  2100: size_tmps = kernel_power_max * sizeof (dcc2_tmp_t);            break;
          case  2500: size_tmps = kernel_power_max * sizeof (wpa_tmp_t);             break;
          case  3200: size_tmps = kernel_power_max * sizeof (bcrypt_tmp_t);          break;
          case  5200: size_tmps = kernel_power_max * sizeof (pwsafe3_tmp_t);         break;
          case  5800: size_tmps = kernel_power_max * sizeof (androidpin_tmp_t);      break;
          case  6211: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case  6212: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case  6213: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case  6221: size_tmps = kernel_power_max * sizeof (tc64_tmp_t);            break;
          case  6222: size_tmps = kernel_power_max * sizeof (tc64_tmp_t);            break;
          case  6223: size_tmps = kernel_power_max * sizeof (tc64_tmp_t);            break;
          case  6231: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case  6232: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case  6233: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case  6241: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case  6242: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case  6243: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case  6300: size_tmps = kernel_power_max * sizeof (md5crypt_tmp_t);        break;
          case  6400: size_tmps = kernel_power_max * sizeof (sha256aix_tmp_t);       break;
          case  6500: size_tmps = kernel_power_max * sizeof (sha512aix_tmp_t);       break;
          case  6600: size_tmps = kernel_power_max * sizeof (agilekey_tmp_t);        break;
          case  6700: size_tmps = kernel_power_max * sizeof (sha1aix_tmp_t);         break;
          case  6800: size_tmps = kernel_power_max * sizeof (lastpass_tmp_t);        break;
          case  7100: size_tmps = kernel_power_max * sizeof (pbkdf2_sha512_tmp_t);   break;
          case  7200: size_tmps = kernel_power_max * sizeof (pbkdf2_sha512_tmp_t);   break;
          case  7400: size_tmps = kernel_power_max * sizeof (sha256crypt_tmp_t);     break;
          case  7900: size_tmps = kernel_power_max * sizeof (drupal7_tmp_t);         break;
          case  8200: size_tmps = kernel_power_max * sizeof (pbkdf2_sha512_tmp_t);   break;
          case  8800: size_tmps = kernel_power_max * sizeof (androidfde_tmp_t);      break;
          case  8900: size_tmps = kernel_power_max * data.scrypt_tmp_size;           break;
          case  9000: size_tmps = kernel_power_max * sizeof (pwsafe2_tmp_t);         break;
          case  9100: size_tmps = kernel_power_max * sizeof (lotus8_tmp_t);          break;
          case  9200: size_tmps = kernel_power_max * sizeof (pbkdf2_sha256_tmp_t);   break;
          case  9300: size_tmps = kernel_power_max * data.scrypt_tmp_size;           break;
          case  9400: size_tmps = kernel_power_max * sizeof (office2007_tmp_t);      break;
          case  9500: size_tmps = kernel_power_max * sizeof (office2010_tmp_t);      break;
          case  9600: size_tmps = kernel_power_max * sizeof (office2013_tmp_t);      break;
          case 10000: size_tmps = kernel_power_max * sizeof (pbkdf2_sha256_tmp_t);   break;
          case 10200: size_tmps = kernel_power_max * sizeof (cram_md5_t);            break;
          case 10300: size_tmps = kernel_power_max * sizeof (saph_sha1_tmp_t);       break;
          case 10500: size_tmps = kernel_power_max * sizeof (pdf14_tmp_t);           break;
          case 10700: size_tmps = kernel_power_max * sizeof (pdf17l8_tmp_t);         break;
          case 10900: size_tmps = kernel_power_max * sizeof (pbkdf2_sha256_tmp_t);   break;
          case 11300: size_tmps = kernel_power_max * sizeof (bitcoin_wallet_tmp_t);  break;
          case 11600: size_tmps = kernel_power_max * sizeof (seven_zip_tmp_t);       break;
          case 11900: size_tmps = kernel_power_max * sizeof (pbkdf2_md5_tmp_t);      break;
          case 12000: size_tmps = kernel_power_max * sizeof (pbkdf2_sha1_tmp_t);     break;
          case 12100: size_tmps = kernel_power_max * sizeof (pbkdf2_sha512_tmp_t);   break;
          case 12200: size_tmps = kernel_power_max * sizeof (ecryptfs_tmp_t);        break;
          case 12300: size_tmps = kernel_power_max * sizeof (oraclet_tmp_t);         break;
          case 12400: size_tmps = kernel_power_max * sizeof (bsdicrypt_tmp_t);       break;
          case 12500: size_tmps = kernel_power_max * sizeof (rar3_tmp_t);            break;
          case 12700: size_tmps = kernel_power_max * sizeof (mywallet_tmp_t);        break;
          case 12800: size_tmps = kernel_power_max * sizeof (pbkdf2_sha256_tmp_t);   break;
          case 12900: size_tmps = kernel_power_max * sizeof (pbkdf2_sha256_tmp_t);   break;
          case 13000: size_tmps = kernel_power_max * sizeof (pbkdf2_sha256_tmp_t);   break;
          case 13200: size_tmps = kernel_power_max * sizeof (axcrypt_tmp_t);         break;
          case 13400: size_tmps = kernel_power_max * sizeof (keepass_tmp_t);         break;
          case 13600: size_tmps = kernel_power_max * sizeof (pbkdf2_sha1_tmp_t);     break;
          case 13711: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13712: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13713: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13721: size_tmps = kernel_power_max * sizeof (tc64_tmp_t);            break;
          case 13722: size_tmps = kernel_power_max * sizeof (tc64_tmp_t);            break;
          case 13723: size_tmps = kernel_power_max * sizeof (tc64_tmp_t);            break;
          case 13731: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13732: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13733: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13741: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13742: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13743: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13751: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13752: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13753: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13761: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13762: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
          case 13763: size_tmps = kernel_power_max * sizeof (tc_tmp_t);              break;
        };

        // size_hooks

        if ((hashconfig->opts_type & OPTS_TYPE_HOOK12) || (hashconfig->opts_type & OPTS_TYPE_HOOK23))
        {
          switch (hashconfig->hash_mode)
          {
          }
        }

        // now check if all device-memory sizes which depend on the kernel_accel_max amplifier are within its boundaries
        // if not, decrease amplifier and try again

        int memory_limit_hit = 0;

        if (size_pws   > device_param->device_maxmem_alloc) memory_limit_hit = 1;
        if (size_tmps  > device_param->device_maxmem_alloc) memory_limit_hit = 1;
        if (size_hooks > device_param->device_maxmem_alloc) memory_limit_hit = 1;

        const u64 size_total
          = bitmap_size
          + bitmap_size
          + bitmap_size
          + bitmap_size
          + bitmap_size
          + bitmap_size
          + bitmap_size
          + bitmap_size
          + size_bfs
          + size_combs
          + size_digests
          + size_esalts
          + size_hooks
          + size_markov_css
          + size_plains
          + size_pws
          + size_pws // not a bug
          + size_results
          + size_root_css
          + size_rules
          + size_rules_c
          + size_salts
          + size_scrypt4
          + size_scrypt4
          + size_scrypt4
          + size_scrypt4
          + size_shown
          + size_tm
          + size_tmps;

        if (size_total > device_param->device_global_mem) memory_limit_hit = 1;

        if (memory_limit_hit == 1)
        {
          kernel_accel_max--;

          continue;
        }

        break;
      }

      if (kernel_accel_max < kernel_accel_min)
      {
        log_error ("- Device #%u: Device does not provide enough allocatable device-memory to handle this attack", device_id + 1);

        return -1;
      }

      device_param->kernel_accel_min = kernel_accel_min;
      device_param->kernel_accel_max = kernel_accel_max;

      /*
      if (kernel_accel_max < kernel_accel)
      {
        if (quiet == 0) log_info ("- Device #%u: Reduced maximum kernel-accel to %u", device_id + 1, kernel_accel_max);

        device_param->kernel_accel = kernel_accel_max;
      }
      */

      device_param->size_bfs     = size_bfs;
      device_param->size_combs   = size_combs;
      device_param->size_rules   = size_rules;
      device_param->size_rules_c = size_rules_c;
      device_param->size_pws     = size_pws;
      device_param->size_tmps    = size_tmps;
      device_param->size_hooks   = size_hooks;

      /**
       * default building options
       */

      if (chdir (cpath_real) == -1)
      {
        log_error ("ERROR: %s: %s", cpath_real, strerror (errno));

        return -1;
      }

      char build_opts[1024] = { 0 };

      #if defined (_WIN)
      snprintf (build_opts, sizeof (build_opts) - 1, "-I \"%s\"", cpath_real);
      #else
      snprintf (build_opts, sizeof (build_opts) - 1, "-I %s", cpath_real);
      #endif

      // include check
      // this test needs to be done manually because of osx opencl runtime
      // if there's a problem with permission, its not reporting back and erroring out silently

      #define files_cnt 15

      const char *files_names[files_cnt] =
      {
        "inc_cipher_aes256.cl",
        "inc_cipher_serpent256.cl",
        "inc_cipher_twofish256.cl",
        "inc_common.cl",
        "inc_comp_multi_bs.cl",
        "inc_comp_multi.cl",
        "inc_comp_single_bs.cl",
        "inc_comp_single.cl",
        "inc_hash_constants.h",
        "inc_hash_functions.cl",
        "inc_rp.cl",
        "inc_rp.h",
        "inc_simd.cl",
        "inc_types.cl",
        "inc_vendor.cl",
      };

      for (int i = 0; i < files_cnt; i++)
      {
        FILE *fd = fopen (files_names[i], "r");

        if (fd == NULL)
        {
          log_error ("ERROR: %s: fopen(): %s", files_names[i], strerror (errno));

          return -1;
        }

        char buf[1];

        size_t n = fread (buf, 1, 1, fd);

        if (n != 1)
        {
          log_error ("ERROR: %s: fread(): %s", files_names[i], strerror (errno));

          return -1;
        }

        fclose (fd);
      }

      // we don't have sm_* on vendors not NV but it doesn't matter

      char build_opts_new[1024] = { 0 };

      #if defined (DEBUG)
      snprintf (build_opts_new, sizeof (build_opts_new) - 1, "%s -D VENDOR_ID=%u -D CUDA_ARCH=%d -D VECT_SIZE=%u -D DEVICE_TYPE=%u -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D KERN_TYPE=%u -D _unroll -cl-std=CL1.1", build_opts, device_param->device_vendor_id, (device_param->sm_major * 100) + device_param->sm_minor, device_param->vector_width, (u32) device_param->device_type, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, hashconfig->dgst_size / 4, hashconfig->kern_type);
      #else
      snprintf (build_opts_new, sizeof (build_opts_new) - 1, "%s -D VENDOR_ID=%u -D CUDA_ARCH=%d -D VECT_SIZE=%u -D DEVICE_TYPE=%u -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D KERN_TYPE=%u -D _unroll -cl-std=CL1.1 -w", build_opts, device_param->device_vendor_id, (device_param->sm_major * 100) + device_param->sm_minor, device_param->vector_width, (u32) device_param->device_type, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, hashconfig->dgst_size / 4, hashconfig->kern_type);
      #endif

      strncpy (build_opts, build_opts_new, sizeof (build_opts));

      #if defined (DEBUG)
      log_info ("- Device #%u: build_opts '%s'\n", device_id + 1, build_opts);
      #endif

      /**
       * main kernel
       */

      {
        /**
         * kernel source filename
         */

        char source_file[256] = { 0 };

        generate_source_kernel_filename (hashconfig->attack_exec, attack_kern, hashconfig->kern_type, shared_dir, source_file);

        struct stat sst;

        if (stat (source_file, &sst) == -1)
        {
          log_error ("ERROR: %s: %s", source_file, strerror (errno));

          return -1;
        }

        /**
         * kernel cached filename
         */

        char cached_file[256] = { 0 };

        generate_cached_kernel_filename (hashconfig->attack_exec, attack_kern, hashconfig->kern_type, profile_dir, device_name_chksum, cached_file);

        int cached = 1;

        struct stat cst;

        if ((stat (cached_file, &cst) == -1) || cst.st_size == 0)
        {
          cached = 0;
        }

        /**
         * kernel compile or load
         */

        size_t *kernel_lengths = (size_t *) mymalloc (sizeof (size_t));

        const u8 **kernel_sources = (const u8 **) mymalloc (sizeof (u8 *));

        if (force_jit_compilation == -1)
        {
          if (cached == 0)
          {
            if (quiet == 0) log_info ("- Device #%u: Kernel %s not found in cache! Building may take a while...", device_id + 1, filename_from_filepath (cached_file));

            load_kernel (source_file, 1, kernel_lengths, kernel_sources);

            CL_err = hc_clCreateProgramWithSource (data.ocl, device_param->context, 1, (const char **) kernel_sources, NULL, &device_param->program);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clCreateProgramWithSource(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            CL_err = hc_clBuildProgram (data.ocl, device_param->program, 1, &device_param->device, build_opts, NULL, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clBuildProgram(): %s\n", val2cstr_cl (CL_err));

              //return -1;
            }

            size_t build_log_size = 0;

            /*
            CL_err = hc_clGetProgramBuildInfo (data.ocl, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetProgramBuildInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }
            */

            hc_clGetProgramBuildInfo (data.ocl, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

            #if defined (DEBUG)
            if ((build_log_size != 0) || (CL_err != CL_SUCCESS))
            #else
            if (CL_err != CL_SUCCESS)
            #endif
            {
              char *build_log = (char *) mymalloc (build_log_size + 1);

              CL_err = hc_clGetProgramBuildInfo (data.ocl, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

              if (CL_err != CL_SUCCESS)
              {
                log_error ("ERROR: clGetProgramBuildInfo(): %s\n", val2cstr_cl (CL_err));

                return -1;
              }

              puts (build_log);

              myfree (build_log);
            }

            if (CL_err != CL_SUCCESS)
            {
              device_param->skipped = true;

              log_info ("- Device #%u: Kernel %s build failure. Proceeding without this device.", device_id + 1, source_file);

              continue;
            }

            size_t binary_size;

            CL_err = hc_clGetProgramInfo (data.ocl, device_param->program, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetProgramInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            u8 *binary = (u8 *) mymalloc (binary_size);

            CL_err = hc_clGetProgramInfo (data.ocl, device_param->program, CL_PROGRAM_BINARIES, sizeof (binary), &binary, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetProgramInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            writeProgramBin (cached_file, binary, binary_size);

            local_free (binary);
          }
          else
          {
            #if defined (DEBUG)
            log_info ("- Device #%u: Kernel %s (%ld bytes)", device_id + 1, cached_file, cst.st_size);
            #endif

            load_kernel (cached_file, 1, kernel_lengths, kernel_sources);

            CL_err = hc_clCreateProgramWithBinary (data.ocl, device_param->context, 1, &device_param->device, kernel_lengths, (const u8 **) kernel_sources, NULL, &device_param->program);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clCreateProgramWithBinary(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            CL_err = hc_clBuildProgram (data.ocl, device_param->program, 1, &device_param->device, build_opts, NULL, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clBuildProgram(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }
          }
        }
        else
        {
          #if defined (DEBUG)
          log_info ("- Device #%u: Kernel %s (%ld bytes)", device_id + 1, source_file, sst.st_size);
          #endif

          load_kernel (source_file, 1, kernel_lengths, kernel_sources);

          CL_err = hc_clCreateProgramWithSource (data.ocl, device_param->context, 1, (const char **) kernel_sources, NULL, &device_param->program);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateProgramWithSource(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          char build_opts_update[1024] = { 0 };

          if (force_jit_compilation == 1500)
          {
            snprintf (build_opts_update, sizeof (build_opts_update) - 1, "%s -DDESCRYPT_SALT=%u", build_opts, data.salts_buf[0].salt_buf[0]);
          }
          else if (force_jit_compilation == 8900)
          {
            snprintf (build_opts_update, sizeof (build_opts_update) - 1, "%s -DSCRYPT_N=%u -DSCRYPT_R=%u -DSCRYPT_P=%u -DSCRYPT_TMTO=%u -DSCRYPT_TMP_ELEM=%u", build_opts, data.salts_buf[0].scrypt_N, data.salts_buf[0].scrypt_r, data.salts_buf[0].scrypt_p, 1 << data.scrypt_tmto_final, data.scrypt_tmp_size / 16);
          }
          else
          {
            snprintf (build_opts_update, sizeof (build_opts_update) - 1, "%s", build_opts);
          }

          CL_err = hc_clBuildProgram (data.ocl, device_param->program, 1, &device_param->device, build_opts_update, NULL, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clBuildProgram(): %s\n", val2cstr_cl (CL_err));

            //return -1;
          }

          size_t build_log_size = 0;

          /*
          CL_err = hc_clGetProgramBuildInfo (data.ocl, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetProgramBuildInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
          */

          hc_clGetProgramBuildInfo (data.ocl, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          #if defined (DEBUG)
          if ((build_log_size != 0) || (CL_err != CL_SUCCESS))
          #else
          if (CL_err != CL_SUCCESS)
          #endif
          {
            char *build_log = (char *) mymalloc (build_log_size + 1);

            CL_err = hc_clGetProgramBuildInfo (data.ocl, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetProgramBuildInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            puts (build_log);

            myfree (build_log);
          }

          if (CL_err != CL_SUCCESS)
          {
            device_param->skipped = true;

            log_info ("- Device #%u: Kernel %s build failure. Proceeding without this device.", device_id + 1, source_file);
          }
        }

        local_free (kernel_lengths);
        local_free (kernel_sources[0]);
        local_free (kernel_sources);
      }

      /**
       * word generator kernel
       */

      if (attack_mode != ATTACK_MODE_STRAIGHT)
      {
        /**
         * kernel mp source filename
         */

        char source_file[256] = { 0 };

        generate_source_kernel_mp_filename (hashconfig->opti_type, hashconfig->opts_type, shared_dir, source_file);

        struct stat sst;

        if (stat (source_file, &sst) == -1)
        {
          log_error ("ERROR: %s: %s", source_file, strerror (errno));

          return -1;
        }

        /**
         * kernel mp cached filename
         */

        char cached_file[256] = { 0 };

        generate_cached_kernel_mp_filename (hashconfig->opti_type, hashconfig->opts_type, profile_dir, device_name_chksum, cached_file);

        int cached = 1;

        struct stat cst;

        if (stat (cached_file, &cst) == -1)
        {
          cached = 0;
        }

        /**
         * kernel compile or load
         */

        size_t *kernel_lengths = (size_t *) mymalloc (sizeof (size_t));

        const u8 **kernel_sources = (const u8 **) mymalloc (sizeof (u8 *));

        if (cached == 0)
        {
          if (quiet == 0) log_info ("- Device #%u: Kernel %s not found in cache! Building may take a while...", device_id + 1, filename_from_filepath (cached_file));
          if (quiet == 0) log_info ("");

          load_kernel (source_file, 1, kernel_lengths, kernel_sources);

          CL_err = hc_clCreateProgramWithSource (data.ocl, device_param->context, 1, (const char **) kernel_sources, NULL, &device_param->program_mp);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateProgramWithSource(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          CL_err = hc_clBuildProgram (data.ocl, device_param->program_mp, 1, &device_param->device, build_opts, NULL, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clBuildProgram(): %s\n", val2cstr_cl (CL_err));

            //return -1;
          }

          size_t build_log_size = 0;

          /*
          CL_err = hc_clGetProgramBuildInfo (data.ocl, device_param->program_mp, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetProgramBuildInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
          */

          hc_clGetProgramBuildInfo (data.ocl, device_param->program_mp, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          #if defined (DEBUG)
          if ((build_log_size != 0) || (CL_err != CL_SUCCESS))
          #else
          if (CL_err != CL_SUCCESS)
          #endif
          {
            char *build_log = (char *) mymalloc (build_log_size + 1);

            CL_err = hc_clGetProgramBuildInfo (data.ocl, device_param->program_mp, device_param->device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetProgramBuildInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            puts (build_log);

            myfree (build_log);
          }

          if (CL_err != CL_SUCCESS)
          {
            device_param->skipped = true;

            log_info ("- Device #%u: Kernel %s build failure. Proceeding without this device.", device_id + 1, source_file);

            continue;
          }

          size_t binary_size;

          CL_err = hc_clGetProgramInfo (data.ocl, device_param->program_mp, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetProgramInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          u8 *binary = (u8 *) mymalloc (binary_size);

          CL_err = hc_clGetProgramInfo (data.ocl, device_param->program_mp, CL_PROGRAM_BINARIES, sizeof (binary), &binary, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetProgramInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          writeProgramBin (cached_file, binary, binary_size);

          local_free (binary);
        }
        else
        {
          #if defined (DEBUG)
          log_info ("- Device #%u: Kernel %s (%ld bytes)", device_id + 1, cached_file, cst.st_size);
          #endif

          load_kernel (cached_file, 1, kernel_lengths, kernel_sources);

          CL_err = hc_clCreateProgramWithBinary (data.ocl, device_param->context, 1, &device_param->device, kernel_lengths, (const u8 **) kernel_sources, NULL, &device_param->program_mp);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateProgramWithBinary(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          CL_err = hc_clBuildProgram (data.ocl, device_param->program_mp, 1, &device_param->device, build_opts, NULL, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clBuildProgram(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
        }

        local_free (kernel_lengths);
        local_free (kernel_sources[0]);
        local_free (kernel_sources);
      }

      /**
       * amplifier kernel
       */

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {

      }
      else
      {
        /**
         * kernel amp source filename
         */

        char source_file[256] = { 0 };

        generate_source_kernel_amp_filename (attack_kern, shared_dir, source_file);

        struct stat sst;

        if (stat (source_file, &sst) == -1)
        {
          log_error ("ERROR: %s: %s", source_file, strerror (errno));

          return -1;
        }

        /**
         * kernel amp cached filename
         */

        char cached_file[256] = { 0 };

        generate_cached_kernel_amp_filename (attack_kern, profile_dir, device_name_chksum, cached_file);

        int cached = 1;

        struct stat cst;

        if (stat (cached_file, &cst) == -1)
        {
          cached = 0;
        }

        /**
         * kernel compile or load
         */

        size_t *kernel_lengths = (size_t *) mymalloc (sizeof (size_t));

        const u8 **kernel_sources = (const u8 **) mymalloc (sizeof (u8 *));

        if (cached == 0)
        {
          if (quiet == 0) log_info ("- Device #%u: Kernel %s not found in cache! Building may take a while...", device_id + 1, filename_from_filepath (cached_file));
          if (quiet == 0) log_info ("");

          load_kernel (source_file, 1, kernel_lengths, kernel_sources);

          CL_err = hc_clCreateProgramWithSource (data.ocl, device_param->context, 1, (const char **) kernel_sources, NULL, &device_param->program_amp);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateProgramWithSource(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          CL_err = hc_clBuildProgram (data.ocl, device_param->program_amp, 1, &device_param->device, build_opts, NULL, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clBuildProgram(): %s\n", val2cstr_cl (CL_err));

            //return -1;
          }

          size_t build_log_size = 0;

          /*
          CL_err = hc_clGetProgramBuildInfo (data.ocl, device_param->program_amp, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetProgramBuildInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
          */

          hc_clGetProgramBuildInfo (data.ocl, device_param->program_amp, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          #if defined (DEBUG)
          if ((build_log_size != 0) || (CL_err != CL_SUCCESS))
          #else
          if (CL_err != CL_SUCCESS)
          #endif
          {
            char *build_log = (char *) mymalloc (build_log_size + 1);

            CL_err = hc_clGetProgramBuildInfo (data.ocl, device_param->program_amp, device_param->device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetProgramBuildInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            puts (build_log);

            myfree (build_log);
          }

          if (CL_err != CL_SUCCESS)
          {
            device_param->skipped = true;

            log_info ("- Device #%u: Kernel %s build failure. Proceed without this device.", device_id + 1, source_file);

            continue;
          }

          size_t binary_size;

          CL_err = hc_clGetProgramInfo (data.ocl, device_param->program_amp, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetProgramInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          u8 *binary = (u8 *) mymalloc (binary_size);

          CL_err = hc_clGetProgramInfo (data.ocl, device_param->program_amp, CL_PROGRAM_BINARIES, sizeof (binary), &binary, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetProgramInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          writeProgramBin (cached_file, binary, binary_size);

          local_free (binary);
        }
        else
        {
          #if defined (DEBUG)
          if (quiet == 0) log_info ("- Device #%u: Kernel %s (%ld bytes)", device_id + 1, cached_file, cst.st_size);
          #endif

          load_kernel (cached_file, 1, kernel_lengths, kernel_sources);

          CL_err = hc_clCreateProgramWithBinary (data.ocl, device_param->context, 1, &device_param->device, kernel_lengths, (const u8 **) kernel_sources, NULL, &device_param->program_amp);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateProgramWithBinary(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          CL_err = hc_clBuildProgram (data.ocl, device_param->program_amp, 1, &device_param->device, build_opts, NULL, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clBuildProgram(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
        }

        local_free (kernel_lengths);
        local_free (kernel_sources[0]);
        local_free (kernel_sources);
      }

      // return back to the folder we came from initially (workaround)

      if (chdir (cwd) == -1)
      {
        log_error ("ERROR: %s: %s", cwd, strerror (errno));

        return -1;
      }

      // some algorithm collide too fast, make that impossible

      if (benchmark == 1)
      {
        ((uint *) digests_buf)[0] = -1u;
        ((uint *) digests_buf)[1] = -1u;
        ((uint *) digests_buf)[2] = -1u;
        ((uint *) digests_buf)[3] = -1u;
      }

      /**
       * global buffers
       */

      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   size_pws,     NULL, &device_param->d_pws_buf);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   size_pws,     NULL, &device_param->d_pws_amp_buf);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_WRITE,  size_tmps,    NULL, &device_param->d_tmps);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_WRITE,  size_hooks,   NULL, &device_param->d_hooks);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   bitmap_size,  NULL, &device_param->d_bitmap_s1_a);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   bitmap_size,  NULL, &device_param->d_bitmap_s1_b);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   bitmap_size,  NULL, &device_param->d_bitmap_s1_c);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   bitmap_size,  NULL, &device_param->d_bitmap_s1_d);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   bitmap_size,  NULL, &device_param->d_bitmap_s2_a);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   bitmap_size,  NULL, &device_param->d_bitmap_s2_b);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   bitmap_size,  NULL, &device_param->d_bitmap_s2_c);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   bitmap_size,  NULL, &device_param->d_bitmap_s2_d);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_WRITE,  size_plains,  NULL, &device_param->d_plain_bufs);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   size_digests, NULL, &device_param->d_digests_buf);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_WRITE,  size_shown,   NULL, &device_param->d_digests_shown);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY,   size_salts,   NULL, &device_param->d_salt_bufs);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_WRITE,  size_results, NULL, &device_param->d_result);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_WRITE,  size_scrypt4, NULL, &device_param->d_scryptV0_buf);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_WRITE,  size_scrypt4, NULL, &device_param->d_scryptV1_buf);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_WRITE,  size_scrypt4, NULL, &device_param->d_scryptV2_buf);
      CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_WRITE,  size_scrypt4, NULL, &device_param->d_scryptV3_buf);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clCreateBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_bitmap_s1_a,    CL_TRUE, 0, bitmap_size,  bitmap_s1_a,        0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_bitmap_s1_b,    CL_TRUE, 0, bitmap_size,  bitmap_s1_b,        0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_bitmap_s1_c,    CL_TRUE, 0, bitmap_size,  bitmap_s1_c,        0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_bitmap_s1_d,    CL_TRUE, 0, bitmap_size,  bitmap_s1_d,        0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_bitmap_s2_a,    CL_TRUE, 0, bitmap_size,  bitmap_s2_a,        0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_bitmap_s2_b,    CL_TRUE, 0, bitmap_size,  bitmap_s2_b,        0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_bitmap_s2_c,    CL_TRUE, 0, bitmap_size,  bitmap_s2_c,        0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_bitmap_s2_d,    CL_TRUE, 0, bitmap_size,  bitmap_s2_d,        0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_digests_buf,    CL_TRUE, 0, size_digests, data.digests_buf,   0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_digests_shown,  CL_TRUE, 0, size_shown,   data.digests_shown, 0, NULL, NULL);
      CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_salt_bufs,      CL_TRUE, 0, size_salts,   data.salts_buf,     0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      /**
       * special buffers
       */

      if (attack_kern == ATTACK_KERN_STRAIGHT)
      {
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_rules,   NULL, &device_param->d_rules);
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_rules_c, NULL, &device_param->d_rules_c);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_rules, CL_TRUE, 0, size_rules, kernel_rules_buf, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (attack_kern == ATTACK_KERN_COMBI)
      {
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_combs,      NULL, &device_param->d_combs);
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_combs,      NULL, &device_param->d_combs_c);
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_root_css,   NULL, &device_param->d_root_css_buf);
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_markov_css, NULL, &device_param->d_markov_css_buf);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (attack_kern == ATTACK_KERN_BF)
      {
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_bfs,        NULL, &device_param->d_bfs);
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_bfs,        NULL, &device_param->d_bfs_c);
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_tm,         NULL, &device_param->d_tm_c);
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_root_css,   NULL, &device_param->d_root_css_buf);
        CL_err |= hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_markov_css, NULL, &device_param->d_markov_css_buf);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }

      if (size_esalts)
      {
        CL_err = hc_clCreateBuffer (data.ocl, device_param->context, CL_MEM_READ_ONLY, size_esalts, NULL, &device_param->d_esalt_bufs);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        CL_err = hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_esalt_bufs, CL_TRUE, 0, size_esalts, data.esalts_buf, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }

      /**
       * main host data
       */

      pw_t *pws_buf = (pw_t *) mymalloc (size_pws);

      device_param->pws_buf = pws_buf;

      comb_t *combs_buf = (comb_t *) mycalloc (KERNEL_COMBS, sizeof (comb_t));

      device_param->combs_buf = combs_buf;

      void *hooks_buf = mymalloc (size_hooks);

      device_param->hooks_buf = hooks_buf;

      /**
       * kernel args
       */

      device_param->kernel_params_buf32[24] = bitmap_mask;
      device_param->kernel_params_buf32[25] = bitmap_shift1;
      device_param->kernel_params_buf32[26] = bitmap_shift2;
      device_param->kernel_params_buf32[27] = 0; // salt_pos
      device_param->kernel_params_buf32[28] = 0; // loop_pos
      device_param->kernel_params_buf32[29] = 0; // loop_cnt
      device_param->kernel_params_buf32[30] = 0; // kernel_rules_cnt
      device_param->kernel_params_buf32[31] = 0; // digests_cnt
      device_param->kernel_params_buf32[32] = 0; // digests_offset
      device_param->kernel_params_buf32[33] = 0; // combs_mode
      device_param->kernel_params_buf32[34] = 0; // gid_max

      device_param->kernel_params[ 0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                      ? &device_param->d_pws_buf
                                      : &device_param->d_pws_amp_buf;
      device_param->kernel_params[ 1] = &device_param->d_rules_c;
      device_param->kernel_params[ 2] = &device_param->d_combs_c;
      device_param->kernel_params[ 3] = &device_param->d_bfs_c;
      device_param->kernel_params[ 4] = &device_param->d_tmps;
      device_param->kernel_params[ 5] = &device_param->d_hooks;
      device_param->kernel_params[ 6] = &device_param->d_bitmap_s1_a;
      device_param->kernel_params[ 7] = &device_param->d_bitmap_s1_b;
      device_param->kernel_params[ 8] = &device_param->d_bitmap_s1_c;
      device_param->kernel_params[ 9] = &device_param->d_bitmap_s1_d;
      device_param->kernel_params[10] = &device_param->d_bitmap_s2_a;
      device_param->kernel_params[11] = &device_param->d_bitmap_s2_b;
      device_param->kernel_params[12] = &device_param->d_bitmap_s2_c;
      device_param->kernel_params[13] = &device_param->d_bitmap_s2_d;
      device_param->kernel_params[14] = &device_param->d_plain_bufs;
      device_param->kernel_params[15] = &device_param->d_digests_buf;
      device_param->kernel_params[16] = &device_param->d_digests_shown;
      device_param->kernel_params[17] = &device_param->d_salt_bufs;
      device_param->kernel_params[18] = &device_param->d_esalt_bufs;
      device_param->kernel_params[19] = &device_param->d_result;
      device_param->kernel_params[20] = &device_param->d_scryptV0_buf;
      device_param->kernel_params[21] = &device_param->d_scryptV1_buf;
      device_param->kernel_params[22] = &device_param->d_scryptV2_buf;
      device_param->kernel_params[23] = &device_param->d_scryptV3_buf;
      device_param->kernel_params[24] = &device_param->kernel_params_buf32[24];
      device_param->kernel_params[25] = &device_param->kernel_params_buf32[25];
      device_param->kernel_params[26] = &device_param->kernel_params_buf32[26];
      device_param->kernel_params[27] = &device_param->kernel_params_buf32[27];
      device_param->kernel_params[28] = &device_param->kernel_params_buf32[28];
      device_param->kernel_params[29] = &device_param->kernel_params_buf32[29];
      device_param->kernel_params[30] = &device_param->kernel_params_buf32[30];
      device_param->kernel_params[31] = &device_param->kernel_params_buf32[31];
      device_param->kernel_params[32] = &device_param->kernel_params_buf32[32];
      device_param->kernel_params[33] = &device_param->kernel_params_buf32[33];
      device_param->kernel_params[34] = &device_param->kernel_params_buf32[34];

      device_param->kernel_params_mp_buf64[3] = 0;
      device_param->kernel_params_mp_buf32[4] = 0;
      device_param->kernel_params_mp_buf32[5] = 0;
      device_param->kernel_params_mp_buf32[6] = 0;
      device_param->kernel_params_mp_buf32[7] = 0;
      device_param->kernel_params_mp_buf32[8] = 0;

      device_param->kernel_params_mp[0] = NULL;
      device_param->kernel_params_mp[1] = NULL;
      device_param->kernel_params_mp[2] = NULL;
      device_param->kernel_params_mp[3] = &device_param->kernel_params_mp_buf64[3];
      device_param->kernel_params_mp[4] = &device_param->kernel_params_mp_buf32[4];
      device_param->kernel_params_mp[5] = &device_param->kernel_params_mp_buf32[5];
      device_param->kernel_params_mp[6] = &device_param->kernel_params_mp_buf32[6];
      device_param->kernel_params_mp[7] = &device_param->kernel_params_mp_buf32[7];
      device_param->kernel_params_mp[8] = &device_param->kernel_params_mp_buf32[8];

      device_param->kernel_params_mp_l_buf64[3] = 0;
      device_param->kernel_params_mp_l_buf32[4] = 0;
      device_param->kernel_params_mp_l_buf32[5] = 0;
      device_param->kernel_params_mp_l_buf32[6] = 0;
      device_param->kernel_params_mp_l_buf32[7] = 0;
      device_param->kernel_params_mp_l_buf32[8] = 0;
      device_param->kernel_params_mp_l_buf32[9] = 0;

      device_param->kernel_params_mp_l[0] = NULL;
      device_param->kernel_params_mp_l[1] = NULL;
      device_param->kernel_params_mp_l[2] = NULL;
      device_param->kernel_params_mp_l[3] = &device_param->kernel_params_mp_l_buf64[3];
      device_param->kernel_params_mp_l[4] = &device_param->kernel_params_mp_l_buf32[4];
      device_param->kernel_params_mp_l[5] = &device_param->kernel_params_mp_l_buf32[5];
      device_param->kernel_params_mp_l[6] = &device_param->kernel_params_mp_l_buf32[6];
      device_param->kernel_params_mp_l[7] = &device_param->kernel_params_mp_l_buf32[7];
      device_param->kernel_params_mp_l[8] = &device_param->kernel_params_mp_l_buf32[8];
      device_param->kernel_params_mp_l[9] = &device_param->kernel_params_mp_l_buf32[9];

      device_param->kernel_params_mp_r_buf64[3] = 0;
      device_param->kernel_params_mp_r_buf32[4] = 0;
      device_param->kernel_params_mp_r_buf32[5] = 0;
      device_param->kernel_params_mp_r_buf32[6] = 0;
      device_param->kernel_params_mp_r_buf32[7] = 0;
      device_param->kernel_params_mp_r_buf32[8] = 0;

      device_param->kernel_params_mp_r[0] = NULL;
      device_param->kernel_params_mp_r[1] = NULL;
      device_param->kernel_params_mp_r[2] = NULL;
      device_param->kernel_params_mp_r[3] = &device_param->kernel_params_mp_r_buf64[3];
      device_param->kernel_params_mp_r[4] = &device_param->kernel_params_mp_r_buf32[4];
      device_param->kernel_params_mp_r[5] = &device_param->kernel_params_mp_r_buf32[5];
      device_param->kernel_params_mp_r[6] = &device_param->kernel_params_mp_r_buf32[6];
      device_param->kernel_params_mp_r[7] = &device_param->kernel_params_mp_r_buf32[7];
      device_param->kernel_params_mp_r[8] = &device_param->kernel_params_mp_r_buf32[8];

      device_param->kernel_params_amp_buf32[5] = 0; // combs_mode
      device_param->kernel_params_amp_buf32[6] = 0; // gid_max

      device_param->kernel_params_amp[0] = &device_param->d_pws_buf;
      device_param->kernel_params_amp[1] = &device_param->d_pws_amp_buf;
      device_param->kernel_params_amp[2] = &device_param->d_rules_c;
      device_param->kernel_params_amp[3] = &device_param->d_combs_c;
      device_param->kernel_params_amp[4] = &device_param->d_bfs_c;
      device_param->kernel_params_amp[5] = &device_param->kernel_params_amp_buf32[5];
      device_param->kernel_params_amp[6] = &device_param->kernel_params_amp_buf32[6];

      device_param->kernel_params_tm[0] = &device_param->d_bfs_c;
      device_param->kernel_params_tm[1] = &device_param->d_tm_c;

      device_param->kernel_params_memset_buf32[1] = 0; // value
      device_param->kernel_params_memset_buf32[2] = 0; // gid_max

      device_param->kernel_params_memset[0] = NULL;
      device_param->kernel_params_memset[1] = &device_param->kernel_params_memset_buf32[1];
      device_param->kernel_params_memset[2] = &device_param->kernel_params_memset_buf32[2];

      /**
       * kernel name
       */

      size_t kernel_wgs_tmp;

      char kernel_name[64] = { 0 };

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
        {
          snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_s%02d", hashconfig->kern_type, 4);

          CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel1);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_s%02d", hashconfig->kern_type, 8);

          CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel2);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_s%02d", hashconfig->kern_type, 16);

          CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel3);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
        }
        else
        {
          snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_m%02d", hashconfig->kern_type, 4);

          CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel1);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_m%02d", hashconfig->kern_type, 8);

          CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel2);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_m%02d", hashconfig->kern_type, 16);

          CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel3);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
        }

        if (attack_mode == ATTACK_MODE_BF)
        {
          if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
          {
            snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_tm", hashconfig->kern_type);

            CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel_tm);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            CL_err = hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel_tm, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetKernelWorkGroupInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }
          }
        }
      }
      else
      {
        snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_init", hashconfig->kern_type);

        CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel1);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_loop", hashconfig->kern_type);

        CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel2);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_comp", hashconfig->kern_type);

        CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel3);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
        {
          snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_hook12", hashconfig->kern_type);

          CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel12);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          CL_err = hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel12, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetKernelWorkGroupInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
        }

        if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
        {
          snprintf (kernel_name, sizeof (kernel_name) - 1, "m%05d_hook23", hashconfig->kern_type);

          CL_err = hc_clCreateKernel (data.ocl, device_param->program, kernel_name, &device_param->kernel23);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          CL_err = hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel23, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetKernelWorkGroupInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
        }
      }

      CL_err |= hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel1, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);
      CL_err |= hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel2, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);
      CL_err |= hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel3, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetKernelWorkGroupInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      for (uint i = 0; i <= 23; i++)
      {
        CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel1, i, sizeof (cl_mem), device_param->kernel_params[i]);
        CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel2, i, sizeof (cl_mem), device_param->kernel_params[i]);
        CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel3, i, sizeof (cl_mem), device_param->kernel_params[i]);

        if (hashconfig->opts_type & OPTS_TYPE_HOOK12) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel12, i, sizeof (cl_mem), device_param->kernel_params[i]);
        if (hashconfig->opts_type & OPTS_TYPE_HOOK23) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel23, i, sizeof (cl_mem), device_param->kernel_params[i]);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }

      for (uint i = 24; i <= 34; i++)
      {
        CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel1, i, sizeof (cl_uint), device_param->kernel_params[i]);
        CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel2, i, sizeof (cl_uint), device_param->kernel_params[i]);
        CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel3, i, sizeof (cl_uint), device_param->kernel_params[i]);

        if (hashconfig->opts_type & OPTS_TYPE_HOOK12) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel12, i, sizeof (cl_uint), device_param->kernel_params[i]);
        if (hashconfig->opts_type & OPTS_TYPE_HOOK23) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel23, i, sizeof (cl_uint), device_param->kernel_params[i]);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }

      // GPU memset

      CL_err = hc_clCreateKernel (data.ocl, device_param->program, "gpu_memset", &device_param->kernel_memset);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      CL_err = hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel_memset, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetKernelWorkGroupInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_memset, 0, sizeof (cl_mem),  device_param->kernel_params_memset[0]);
      CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_memset, 1, sizeof (cl_uint), device_param->kernel_params_memset[1]);
      CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_memset, 2, sizeof (cl_uint), device_param->kernel_params_memset[2]);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      // MP start

      if (attack_mode == ATTACK_MODE_BF)
      {
        CL_err |= hc_clCreateKernel (data.ocl, device_param->program_mp, "l_markov", &device_param->kernel_mp_l);
        CL_err |= hc_clCreateKernel (data.ocl, device_param->program_mp, "r_markov", &device_param->kernel_mp_r);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        CL_err |= hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel_mp_l, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);
        CL_err |= hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel_mp_r, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetKernelWorkGroupInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
        {
          CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_tm, 0, sizeof (cl_mem), device_param->kernel_params_tm[0]);
          CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_tm, 1, sizeof (cl_mem), device_param->kernel_params_tm[1]);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
        }
      }
      else if (attack_mode == ATTACK_MODE_HYBRID1)
      {
        CL_err = hc_clCreateKernel (data.ocl, device_param->program_mp, "C_markov", &device_param->kernel_mp);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        CL_err = hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel_mp, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetKernelWorkGroupInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (attack_mode == ATTACK_MODE_HYBRID2)
      {
        CL_err = hc_clCreateKernel (data.ocl, device_param->program_mp, "C_markov", &device_param->kernel_mp);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        CL_err = hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel_mp, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetKernelWorkGroupInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        // nothing to do
      }
      else
      {
        CL_err = hc_clCreateKernel (data.ocl, device_param->program_amp, "amp", &device_param->kernel_amp);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clCreateKernel(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        CL_err = hc_clGetKernelWorkGroupInfo (data.ocl, device_param->kernel_amp, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (size_t), &kernel_wgs_tmp, NULL); kernel_threads = MIN (kernel_threads, kernel_wgs_tmp);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetKernelWorkGroupInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        // nothing to do
      }
      else
      {
        for (uint i = 0; i < 5; i++)
        {
          CL_err = hc_clSetKernelArg (data.ocl, device_param->kernel_amp, i, sizeof (cl_mem), device_param->kernel_params_amp[i]);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
        }

        for (uint i = 5; i < 7; i++)
        {
          CL_err = hc_clSetKernelArg (data.ocl, device_param->kernel_amp, i, sizeof (cl_uint), device_param->kernel_params_amp[i]);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }
        }
      }

      // maybe this has been updated by clGetKernelWorkGroupInfo()
      // value can only be decreased, so we don't need to reallocate buffers

      device_param->kernel_threads = kernel_threads;

      // zero some data buffers

      run_kernel_bzero (device_param, device_param->d_pws_buf,        size_pws);
      run_kernel_bzero (device_param, device_param->d_pws_amp_buf,    size_pws);
      run_kernel_bzero (device_param, device_param->d_tmps,           size_tmps);
      run_kernel_bzero (device_param, device_param->d_hooks,          size_hooks);
      run_kernel_bzero (device_param, device_param->d_plain_bufs,     size_plains);
      run_kernel_bzero (device_param, device_param->d_result,         size_results);

      /**
       * special buffers
       */

      if (attack_kern == ATTACK_KERN_STRAIGHT)
      {
        run_kernel_bzero (device_param, device_param->d_rules_c, size_rules_c);
      }
      else if (attack_kern == ATTACK_KERN_COMBI)
      {
        run_kernel_bzero (device_param, device_param->d_combs,          size_combs);
        run_kernel_bzero (device_param, device_param->d_combs_c,        size_combs);
        run_kernel_bzero (device_param, device_param->d_root_css_buf,   size_root_css);
        run_kernel_bzero (device_param, device_param->d_markov_css_buf, size_markov_css);
      }
      else if (attack_kern == ATTACK_KERN_BF)
      {
        run_kernel_bzero (device_param, device_param->d_bfs,            size_bfs);
        run_kernel_bzero (device_param, device_param->d_bfs_c,          size_bfs);
        run_kernel_bzero (device_param, device_param->d_tm_c,           size_tm);
        run_kernel_bzero (device_param, device_param->d_root_css_buf,   size_root_css);
        run_kernel_bzero (device_param, device_param->d_markov_css_buf, size_markov_css);
      }

      #if defined(HAVE_HWMON)

      /**
       * Store initial fanspeed if gpu_temp_retain is enabled
       */

      if (gpu_temp_disable == 0)
      {
        if (gpu_temp_retain != 0)
        {
          hc_thread_mutex_lock (mux_hwmon);

          if (data.hm_device[device_id].fan_get_supported == 1)
          {
            const int fanspeed  = hm_get_fanspeed_with_device_id  (device_id);
            const int fanpolicy = hm_get_fanpolicy_with_device_id (device_id);

            // we also set it to tell the OS we take control over the fan and it's automatic controller
            // if it was set to automatic. we do not control user-defined fanspeeds.

            if (fanpolicy == 1)
            {
              data.hm_device[device_id].fan_set_supported = 1;

              int rc = -1;

              if (device_param->device_vendor_id == VENDOR_ID_AMD)
              {
                rc = hm_set_fanspeed_with_device_id_adl (device_id, fanspeed, 1);
              }
              else if (device_param->device_vendor_id == VENDOR_ID_NV)
              {
                #if defined (__linux__)
                rc = set_fan_control (data.hm_xnvctrl, data.hm_device[device_id].xnvctrl, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_TRUE);
                #endif

                #if defined (_WIN)
                rc = hm_set_fanspeed_with_device_id_nvapi (device_id, fanspeed, 1);
                #endif
              }

              if (rc == 0)
              {
                data.hm_device[device_id].fan_set_supported = 1;
              }
              else
              {
                log_info ("WARNING: Failed to set initial fan speed for device #%u", device_id + 1);

                data.hm_device[device_id].fan_set_supported = 0;
              }
            }
            else
            {
              data.hm_device[device_id].fan_set_supported = 0;
            }
          }

          hc_thread_mutex_unlock (mux_hwmon);
        }
      }

      #endif // HAVE_HWMON
    }

    if (data.quiet == 0) log_info_nn ("");

    /**
     * In benchmark-mode, inform user which algorithm is checked
     */

    if (benchmark == 1)
    {
      if (machine_readable == 0)
      {
        quiet = 0;

        data.quiet = quiet;

        char *hash_type = strhashtype (hashconfig->hash_mode); // not a bug

        log_info ("Hashtype: %s", hash_type);
        log_info ("");
      }
    }

    /**
     * keep track of the progress
     */

    data.words_progress_done     = (u64 *) mycalloc (data.salts_cnt, sizeof (u64));
    data.words_progress_rejected = (u64 *) mycalloc (data.salts_cnt, sizeof (u64));
    data.words_progress_restored = (u64 *) mycalloc (data.salts_cnt, sizeof (u64));

    /**
     * open filehandles
     */

    #if defined (_WIN)
    if (_setmode (_fileno (stdin), _O_BINARY) == -1)
    {
      log_error ("ERROR: %s: %s", "stdin", strerror (errno));

      return -1;
    }

    if (_setmode (_fileno (stdout), _O_BINARY) == -1)
    {
      log_error ("ERROR: %s: %s", "stdout", strerror (errno));

      return -1;
    }

    if (_setmode (_fileno (stderr), _O_BINARY) == -1)
    {
      log_error ("ERROR: %s: %s", "stderr", strerror (errno));

      return -1;
    }
    #endif

    /**
     * dictionary pad
     */

    segment_size *= (1024 * 1024);

    data.segment_size = segment_size;

    wl_data_t *wl_data = (wl_data_t *) mymalloc (sizeof (wl_data_t));

    wl_data->buf   = (char *) mymalloc (segment_size);
    wl_data->avail = segment_size;
    wl_data->incr  = segment_size;
    wl_data->cnt   = 0;
    wl_data->pos   = 0;

    cs_t  *css_buf   = NULL;
    uint   css_cnt   = 0;
    uint   dictcnt   = 0;
    uint   maskcnt   = 1;
    char **masks     = NULL;
    char **dictfiles = NULL;

    uint   mask_from_file = 0;

    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (wordlist_mode == WL_MODE_FILE)
      {
        int wls_left = myargc - (optind + 1);

        for (int i = 0; i < wls_left; i++)
        {
          char *l0_filename = myargv[optind + 1 + i];

          struct stat l0_stat;

          if (stat (l0_filename, &l0_stat) == -1)
          {
            log_error ("ERROR: %s: %s", l0_filename, strerror (errno));

            return -1;
          }

          uint is_dir = S_ISDIR (l0_stat.st_mode);

          if (is_dir == 0)
          {
            dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

            dictcnt++;

            dictfiles[dictcnt - 1] = l0_filename;
          }
          else
          {
            // do not allow --keyspace w/ a directory

            if (keyspace == 1)
            {
              log_error ("ERROR: Keyspace parameter is not allowed together with a directory");

              return -1;
            }

            char **dictionary_files = NULL;

            dictionary_files = scan_directory (l0_filename);

            if (dictionary_files != NULL)
            {
              qsort (dictionary_files, count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

              for (int d = 0; dictionary_files[d] != NULL; d++)
              {
                char *l1_filename = dictionary_files[d];

                struct stat l1_stat;

                if (stat (l1_filename, &l1_stat) == -1)
                {
                  log_error ("ERROR: %s: %s", l1_filename, strerror (errno));

                  return -1;
                }

                if (S_ISREG (l1_stat.st_mode))
                {
                  dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

                  dictcnt++;

                  dictfiles[dictcnt - 1] = mystrdup (l1_filename);
                }
              }
            }

            local_free (dictionary_files);
          }
        }

        if (dictcnt < 1)
        {
          log_error ("ERROR: No usable dictionary file found.");

          return -1;
        }
      }
      else if (wordlist_mode == WL_MODE_STDIN)
      {
        dictcnt = 1;
      }
    }
    else if (attack_mode == ATTACK_MODE_COMBI)
    {
      // display

      char *dictfile1 = myargv[optind + 1 + 0];
      char *dictfile2 = myargv[optind + 1 + 1];

      // find the bigger dictionary and use as base

      FILE *fp1 = NULL;
      FILE *fp2 = NULL;

      struct stat tmp_stat;

      if ((fp1 = fopen (dictfile1, "rb")) == NULL)
      {
        log_error ("ERROR: %s: %s", dictfile1, strerror (errno));

        return -1;
      }

      if (stat (dictfile1, &tmp_stat) == -1)
      {
        log_error ("ERROR: %s: %s", dictfile1, strerror (errno));

        fclose (fp1);

        return -1;
      }

      if (S_ISDIR (tmp_stat.st_mode))
      {
        log_error ("ERROR: %s must be a regular file", dictfile1, strerror (errno));

        fclose (fp1);

        return -1;
      }

      if ((fp2 = fopen (dictfile2, "rb")) == NULL)
      {
        log_error ("ERROR: %s: %s", dictfile2, strerror (errno));

        fclose (fp1);

        return -1;
      }

      if (stat (dictfile2, &tmp_stat) == -1)
      {
        log_error ("ERROR: %s: %s", dictfile2, strerror (errno));

        fclose (fp1);
        fclose (fp2);

        return -1;
      }

      if (S_ISDIR (tmp_stat.st_mode))
      {
        log_error ("ERROR: %s must be a regular file", dictfile2, strerror (errno));

        fclose (fp1);
        fclose (fp2);

        return -1;
      }

      data.combs_cnt = 1;

      data.quiet = 1;

      const u64 words1_cnt = count_words (wl_data, fp1, dictfile1, dictstat_ctx);

      data.quiet = quiet;

      if (words1_cnt == 0)
      {
        log_error ("ERROR: %s: empty file", dictfile1);

        fclose (fp1);
        fclose (fp2);

        return -1;
      }

      data.combs_cnt = 1;

      data.quiet = 1;

      const u64 words2_cnt = count_words (wl_data, fp2, dictfile2, dictstat_ctx);

      data.quiet = quiet;

      if (words2_cnt == 0)
      {
        log_error ("ERROR: %s: empty file", dictfile2);

        fclose (fp1);
        fclose (fp2);

        return -1;
      }

      fclose (fp1);
      fclose (fp2);

      data.dictfile  = dictfile1;
      data.dictfile2 = dictfile2;

      if (words1_cnt >= words2_cnt)
      {
        data.combs_cnt  = words2_cnt;
        data.combs_mode = COMBINATOR_MODE_BASE_LEFT;

        dictfiles = &data.dictfile;

        dictcnt = 1;
      }
      else
      {
        data.combs_cnt  = words1_cnt;
        data.combs_mode = COMBINATOR_MODE_BASE_RIGHT;

        dictfiles = &data.dictfile2;

        dictcnt = 1;

        // we also have to switch wordlist related rules!

        char *tmpc = data.rule_buf_l;

        data.rule_buf_l = data.rule_buf_r;
        data.rule_buf_r = tmpc;

        int   tmpi = data.rule_len_l;

        data.rule_len_l = data.rule_len_r;
        data.rule_len_r = tmpi;
      }
    }
    else if (attack_mode == ATTACK_MODE_BF)
    {
      char *mask = NULL;

      maskcnt = 0;

      if (benchmark == 0)
      {
        mask = myargv[optind + 1];

        masks = (char **) mymalloc (INCR_MASKS * sizeof (char *));

        if ((optind + 2) <= myargc)
        {
          struct stat file_stat;

          if (stat (mask, &file_stat) == -1)
          {
            maskcnt = 1;

            masks[maskcnt - 1] = mystrdup (mask);
          }
          else
          {
            int wls_left = myargc - (optind + 1);

            uint masks_avail = INCR_MASKS;

            for (int i = 0; i < wls_left; i++)
            {
              if (i != 0)
              {
                mask = myargv[optind + 1 + i];

                if (stat (mask, &file_stat) == -1)
                {
                  log_error ("ERROR: %s: %s", mask, strerror (errno));

                  return -1;
                }
              }

              uint is_file = S_ISREG (file_stat.st_mode);

              if (is_file == 1)
              {
                FILE *mask_fp;

                if ((mask_fp = fopen (mask, "r")) == NULL)
                {
                  log_error ("ERROR: %s: %s", mask, strerror (errno));

                  return -1;
                }

                char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

                while (!feof (mask_fp))
                {
                  memset (line_buf, 0, HCBUFSIZ_LARGE);

                  int line_len = fgetl (mask_fp, line_buf);

                  if (line_len == 0) continue;

                  if (line_buf[0] == '#') continue;

                  if (masks_avail == maskcnt)
                  {
                    masks = (char **) myrealloc (masks, masks_avail * sizeof (char *), INCR_MASKS * sizeof (char *));

                    masks_avail += INCR_MASKS;
                  }

                  masks[maskcnt] = mystrdup (line_buf);

                  maskcnt++;
                }

                myfree (line_buf);

                fclose (mask_fp);
              }
              else
              {
                log_error ("ERROR: %s: unsupported file-type", mask);

                return -1;
              }
            }

            mask_from_file = 1;
          }
        }
        else
        {
          custom_charset_1 = (char *) "?l?d?u";
          custom_charset_2 = (char *) "?l?d";
          custom_charset_3 = (char *) "?l?d*!$@_";

          mp_setup_usr (mp_sys, mp_usr, custom_charset_1, 0, hashconfig);
          mp_setup_usr (mp_sys, mp_usr, custom_charset_2, 1, hashconfig);
          mp_setup_usr (mp_sys, mp_usr, custom_charset_3, 2, hashconfig);

          masks[maskcnt] = mystrdup ("?1?2?2?2?2?2?2?3?3?3?3?d?d?d?d");

          wordlist_mode = WL_MODE_MASK;

          data.wordlist_mode = wordlist_mode;

          increment = 1;

          maskcnt = 1;
        }
      }
      else
      {
        /**
         * generate full masks and charsets
         */

        mask = hashconfig_benchmark_mask (hashconfig);

        pw_min = mp_get_length (mask);
        pw_max = pw_min;

        masks = (char **) mymalloc (sizeof (char *));

        maskcnt = 1;

        masks[maskcnt - 1] = mystrdup (mask);

        wordlist_mode = WL_MODE_MASK;

        data.wordlist_mode = wordlist_mode;

        increment = 1;
      }

      dictfiles = (char **) mycalloc (pw_max, sizeof (char *));

      if (increment)
      {
        if (increment_min > pw_min) pw_min = increment_min;

        if (increment_max < pw_max) pw_max = increment_max;
      }
    }
    else if (attack_mode == ATTACK_MODE_HYBRID1)
    {
      data.combs_mode = COMBINATOR_MODE_BASE_LEFT;

      // display

      char *mask = myargv[myargc - 1];

      maskcnt = 0;

      masks = (char **) mymalloc (1 * sizeof (char *));

      // mod

      struct stat file_stat;

      if (stat (mask, &file_stat) == -1)
      {
        maskcnt = 1;

        masks[maskcnt - 1] = mystrdup (mask);
      }
      else
      {
        uint is_file = S_ISREG (file_stat.st_mode);

        if (is_file == 1)
        {
          FILE *mask_fp;

          if ((mask_fp = fopen (mask, "r")) == NULL)
          {
            log_error ("ERROR: %s: %s", mask, strerror (errno));

            return -1;
          }

          char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

          uint masks_avail = 1;

          while (!feof (mask_fp))
          {
            memset (line_buf, 0, HCBUFSIZ_LARGE);

            int line_len = fgetl (mask_fp, line_buf);

            if (line_len == 0) continue;

            if (line_buf[0] == '#') continue;

            if (masks_avail == maskcnt)
            {
              masks = (char **) myrealloc (masks, masks_avail * sizeof (char *), INCR_MASKS * sizeof (char *));

              masks_avail += INCR_MASKS;
            }

            masks[maskcnt] = mystrdup (line_buf);

            maskcnt++;
          }

          myfree (line_buf);

          fclose (mask_fp);

          mask_from_file = 1;
        }
        else
        {
          maskcnt = 1;

          masks[maskcnt - 1] = mystrdup (mask);
        }
      }

      // base

      int wls_left = myargc - (optind + 2);

      for (int i = 0; i < wls_left; i++)
      {
        char *filename = myargv[optind + 1 + i];

        struct stat file_stat;

        if (stat (filename, &file_stat) == -1)
        {
          log_error ("ERROR: %s: %s", filename, strerror (errno));

          return -1;
        }

        uint is_dir = S_ISDIR (file_stat.st_mode);

        if (is_dir == 0)
        {
          dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

          dictcnt++;

          dictfiles[dictcnt - 1] = filename;
        }
        else
        {
          // do not allow --keyspace w/ a directory

          if (keyspace == 1)
          {
            log_error ("ERROR: Keyspace parameter is not allowed together with a directory");

            return -1;
          }

          char **dictionary_files = NULL;

          dictionary_files = scan_directory (filename);

          if (dictionary_files != NULL)
          {
            qsort (dictionary_files, count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

            for (int d = 0; dictionary_files[d] != NULL; d++)
            {
              char *l1_filename = dictionary_files[d];

              struct stat l1_stat;

              if (stat (l1_filename, &l1_stat) == -1)
              {
                log_error ("ERROR: %s: %s", l1_filename, strerror (errno));

                return -1;
              }

              if (S_ISREG (l1_stat.st_mode))
              {
                dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

                dictcnt++;

                dictfiles[dictcnt - 1] = mystrdup (l1_filename);
              }
            }
          }

          local_free (dictionary_files);
        }
      }

      if (dictcnt < 1)
      {
        log_error ("ERROR: No usable dictionary file found.");

        return -1;
      }

      if (increment)
      {
        maskcnt = 0;

        uint mask_min = increment_min; // we can't reject smaller masks here
        uint mask_max = (increment_max < pw_max) ? increment_max : pw_max;

        for (uint mask_cur = mask_min; mask_cur <= mask_max; mask_cur++)
        {
          char *cur_mask = mp_get_truncated_mask (mask, strlen (mask), mask_cur);

          if (cur_mask == NULL) break;

          masks[maskcnt] = cur_mask;

          maskcnt++;

          masks = (char **) myrealloc (masks, maskcnt * sizeof (char *), sizeof (char *));
        }
      }
    }
    else if (attack_mode == ATTACK_MODE_HYBRID2)
    {
      data.combs_mode = COMBINATOR_MODE_BASE_RIGHT;

      // display

      char *mask = myargv[optind + 1 + 0];

      maskcnt = 0;

      masks = (char **) mymalloc (1 * sizeof (char *));

      // mod

      struct stat file_stat;

      if (stat (mask, &file_stat) == -1)
      {
        maskcnt = 1;

        masks[maskcnt - 1] = mystrdup (mask);
      }
      else
      {
        uint is_file = S_ISREG (file_stat.st_mode);

        if (is_file == 1)
        {
          FILE *mask_fp;

          if ((mask_fp = fopen (mask, "r")) == NULL)
          {
            log_error ("ERROR: %s: %s", mask, strerror (errno));

            return -1;
          }

          char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

          uint masks_avail = 1;

          while (!feof (mask_fp))
          {
            memset (line_buf, 0, HCBUFSIZ_LARGE);

            int line_len = fgetl (mask_fp, line_buf);

            if (line_len == 0) continue;

            if (line_buf[0] == '#') continue;

            if (masks_avail == maskcnt)
            {
              masks = (char **) myrealloc (masks, masks_avail * sizeof (char *), INCR_MASKS * sizeof (char *));

              masks_avail += INCR_MASKS;
            }

            masks[maskcnt] = mystrdup (line_buf);

            maskcnt++;
          }

          myfree (line_buf);

          fclose (mask_fp);

          mask_from_file = 1;
        }
        else
        {
          maskcnt = 1;

          masks[maskcnt - 1] = mystrdup (mask);
        }
      }

      // base

      int wls_left = myargc - (optind + 2);

      for (int i = 0; i < wls_left; i++)
      {
        char *filename = myargv[optind + 2 + i];

        struct stat file_stat;

        if (stat (filename, &file_stat) == -1)
        {
          log_error ("ERROR: %s: %s", filename, strerror (errno));

          return -1;
        }

        uint is_dir = S_ISDIR (file_stat.st_mode);

        if (is_dir == 0)
        {
          dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

          dictcnt++;

          dictfiles[dictcnt - 1] = filename;
        }
        else
        {
          // do not allow --keyspace w/ a directory

          if (keyspace == 1)
          {
            log_error ("ERROR: Keyspace parameter is not allowed together with a directory");

            return -1;
          }

          char **dictionary_files = NULL;

          dictionary_files = scan_directory (filename);

          if (dictionary_files != NULL)
          {
            qsort (dictionary_files, count_dictionaries (dictionary_files), sizeof (char *), sort_by_stringptr);

            for (int d = 0; dictionary_files[d] != NULL; d++)
            {
              char *l1_filename = dictionary_files[d];

              struct stat l1_stat;

              if (stat (l1_filename, &l1_stat) == -1)
              {
                log_error ("ERROR: %s: %s", l1_filename, strerror (errno));

                return -1;
              }

              if (S_ISREG (l1_stat.st_mode))
              {
                dictfiles = (char **) myrealloc (dictfiles, dictcnt * sizeof (char *), sizeof (char *));

                dictcnt++;

                dictfiles[dictcnt - 1] = mystrdup (l1_filename);
              }
            }
          }

          local_free (dictionary_files);
        }
      }

      if (dictcnt < 1)
      {
        log_error ("ERROR: No usable dictionary file found.");

        return -1;
      }

      if (increment)
      {
        maskcnt = 0;

        uint mask_min = increment_min; // we can't reject smaller masks here
        uint mask_max = (increment_max < pw_max) ? increment_max : pw_max;

        for (uint mask_cur = mask_min; mask_cur <= mask_max; mask_cur++)
        {
          char *cur_mask = mp_get_truncated_mask (mask, strlen (mask), mask_cur);

          if (cur_mask == NULL) break;

          masks[maskcnt] = cur_mask;

          maskcnt++;

          masks = (char **) myrealloc (masks, maskcnt * sizeof (char *), sizeof (char *));
        }
      }
    }

    data.pw_min = pw_min;
    data.pw_max = pw_max;

    /**
     * weak hash check
     */

    if (weak_hash_threshold >= salts_cnt)
    {
      hc_device_param_t *device_param = NULL;

      for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
      {
        device_param = &data.devices_param[device_id];

        if (device_param->skipped) continue;

        break;
      }

      if (data.quiet == 0) log_info_nn ("Checking for weak hashes...");

      for (uint salt_pos = 0; salt_pos < salts_cnt; salt_pos++)
      {
        weak_hash_check (device_param, hashconfig, salt_pos);
      }

      // Display hack, guarantee that there is at least one \r before real start

      //if (data.quiet == 0) log_info ("");
    }

    /**
     * status and monitor threads
     */

    if ((data.devices_status != STATUS_BYPASS) && (data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
    {
      data.devices_status = STATUS_STARTING;
    }

    uint inner_threads_cnt = 0;

    hc_thread_t *inner_threads = (hc_thread_t *) mycalloc (10, sizeof (hc_thread_t));

    data.shutdown_inner = 0;

    /**
      * Outfile remove
      */

    if (keyspace == 0 && benchmark == 0 && stdout_flag == 0)
    {
      hc_thread_create (inner_threads[inner_threads_cnt], thread_monitor, NULL);

      inner_threads_cnt++;

      if (outfile_check_timer != 0)
      {
        if (data.outfile_check_directory != NULL)
        {
          if ((hashconfig->hash_mode != 5200) &&
              !((hashconfig->hash_mode >=  6200) && (hashconfig->hash_mode <=  6299)) &&
              !((hashconfig->hash_mode >= 13700) && (hashconfig->hash_mode <= 13799)) &&
              (hashconfig->hash_mode != 9000))
          {
            hc_thread_create (inner_threads[inner_threads_cnt], thread_outfile_remove, NULL);

            inner_threads_cnt++;
          }
          else
          {
            outfile_check_timer = 0;
          }
        }
        else
        {
          outfile_check_timer = 0;
        }
      }
    }

    data.outfile_check_timer = outfile_check_timer;

    /**
     * main loop
     */

    if (data.quiet == 0)
    {
      if (potfile_remove_cracks > 0)
      {
        if (potfile_remove_cracks == 1) log_info ("INFO: Removed 1 hash found in potfile\n");
        else                            log_info ("INFO: Removed %d hashes found in potfile\n", potfile_remove_cracks);
      }
    }

    potfile_write_open (potfile_ctx);

    char **induction_dictionaries = NULL;

    int induction_dictionaries_cnt = 0;

    hcstat_table_t *root_table_buf   = NULL;
    hcstat_table_t *markov_table_buf = NULL;

    uint initial_restore_done = 0;

    data.maskcnt = maskcnt;

    for (uint maskpos = rd->maskpos; maskpos < maskcnt; maskpos++)
    {
      if (data.devices_status == STATUS_CRACKED) continue;
      if (data.devices_status == STATUS_ABORTED) continue;
      if (data.devices_status == STATUS_QUIT)    continue;

      if (maskpos > rd->maskpos)
      {
        rd->dictpos = 0;
      }

      rd->maskpos  = maskpos;
      data.maskpos = maskpos;

      if (attack_mode == ATTACK_MODE_HYBRID1 || attack_mode == ATTACK_MODE_HYBRID2 || attack_mode == ATTACK_MODE_BF)
      {
        char *mask = masks[maskpos];

        if (mask_from_file == 1)
        {
          if (mask[0] == '\\' && mask[1] == '#') mask++; // escaped comment sign (sharp) "\#"

          char *str_ptr;
          uint  str_pos;

          uint mask_offset = 0;

          uint separator_cnt;

          for (separator_cnt = 0; separator_cnt < 4; separator_cnt++)
          {
            str_ptr = strstr (mask + mask_offset, ",");

            if (str_ptr == NULL) break;

            str_pos = str_ptr - mask;

            // escaped separator, i.e. "\,"

            if (str_pos > 0)
            {
              if (mask[str_pos - 1] == '\\')
              {
                separator_cnt --;

                mask_offset = str_pos + 1;

                continue;
              }
            }

            // reset the offset

            mask_offset = 0;

            mask[str_pos] = '\0';

            switch (separator_cnt)
            {
              case 0:
                mp_reset_usr (mp_usr, 0);

                custom_charset_1 = mask;
                mp_setup_usr (mp_sys, mp_usr, custom_charset_1, 0, hashconfig);
                break;

              case 1:
                mp_reset_usr (mp_usr, 1);

                custom_charset_2 = mask;
                mp_setup_usr (mp_sys, mp_usr, custom_charset_2, 1, hashconfig);
                break;

              case 2:
                mp_reset_usr (mp_usr, 2);

                custom_charset_3 = mask;
                mp_setup_usr (mp_sys, mp_usr, custom_charset_3, 2, hashconfig);
                break;

              case 3:
                mp_reset_usr (mp_usr, 3);

                custom_charset_4 = mask;
                mp_setup_usr (mp_sys, mp_usr, custom_charset_4, 3, hashconfig);
                break;
            }

            mask = mask + str_pos + 1;
          }

          /**
           * What follows is a very special case where "\," is within the mask field of a line in a .hcmask file only because otherwise (without the "\")
           * it would be interpreted as a custom charset definition.
           *
           * We need to replace all "\," with just "," within the mask (but allow the special case "\\," which means "\" followed by ",")
           * Note: "\\" is not needed to replace all "\" within the mask! The meaning of "\\" within a line containing the string "\\," is just to allow "\" followed by ","
           */

          uint mask_len_cur = strlen (mask);

          uint mask_out_pos = 0;
          char mask_prev = 0;

          for (uint mask_iter = 0; mask_iter < mask_len_cur; mask_iter++, mask_out_pos++)
          {
            if (mask[mask_iter] == ',')
            {
              if (mask_prev == '\\')
              {
                mask_out_pos -= 1; // this means: skip the previous "\"
              }
            }

            mask_prev = mask[mask_iter];

            mask[mask_out_pos] = mask[mask_iter];
          }

          mask[mask_out_pos] = '\0';
        }

        if ((attack_mode == ATTACK_MODE_HYBRID1) || (attack_mode == ATTACK_MODE_HYBRID2))
        {
          if (maskpos > 0)
          {
            local_free (css_buf);
            local_free (data.root_css_buf);
            local_free (data.markov_css_buf);

            local_free (masks[maskpos - 1]);
          }

          css_buf = mp_gen_css (mask, strlen (mask), mp_sys, mp_usr, &css_cnt, hashconfig);

          data.mask = mask;
          data.css_cnt = css_cnt;
          data.css_buf = css_buf;

          uint uniq_tbls[SP_PW_MAX][CHARSIZ] = { { 0 } };

          mp_css_to_uniq_tbl (css_cnt, css_buf, uniq_tbls);

          if (root_table_buf   == NULL) root_table_buf   = (hcstat_table_t *) mycalloc (SP_ROOT_CNT,   sizeof (hcstat_table_t));
          if (markov_table_buf == NULL) markov_table_buf = (hcstat_table_t *) mycalloc (SP_MARKOV_CNT, sizeof (hcstat_table_t));

          sp_setup_tbl (shared_dir, markov_hcstat, markov_disable, markov_classic, root_table_buf, markov_table_buf);

          markov_threshold = (markov_threshold != 0) ? markov_threshold : CHARSIZ;

          cs_t *root_css_buf   = (cs_t *) mycalloc (SP_PW_MAX,           sizeof (cs_t));
          cs_t *markov_css_buf = (cs_t *) mycalloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

          data.root_css_buf   = root_css_buf;
          data.markov_css_buf = markov_css_buf;

          sp_tbl_to_css (root_table_buf, markov_table_buf, root_css_buf, markov_css_buf, markov_threshold, uniq_tbls);

          data.combs_cnt = sp_get_sum (0, css_cnt, root_css_buf);

          local_free (root_table_buf);
          local_free (markov_table_buf);

          // args

          for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
          {
            hc_device_param_t *device_param = &data.devices_param[device_id];

            if (device_param->skipped) continue;

            device_param->kernel_params_mp[0] = &device_param->d_combs;
            device_param->kernel_params_mp[1] = &device_param->d_root_css_buf;
            device_param->kernel_params_mp[2] = &device_param->d_markov_css_buf;

            device_param->kernel_params_mp_buf64[3] = 0;
            device_param->kernel_params_mp_buf32[4] = css_cnt;
            device_param->kernel_params_mp_buf32[5] = 0;
            device_param->kernel_params_mp_buf32[6] = 0;
            device_param->kernel_params_mp_buf32[7] = 0;

            if (attack_mode == ATTACK_MODE_HYBRID1)
            {
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)     device_param->kernel_params_mp_buf32[5] = full01;
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)     device_param->kernel_params_mp_buf32[5] = full80;
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS14) device_param->kernel_params_mp_buf32[6] = 1;
              if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS15) device_param->kernel_params_mp_buf32[7] = 1;
            }
            else if (attack_mode == ATTACK_MODE_HYBRID2)
            {
              device_param->kernel_params_mp_buf32[5] = 0;
              device_param->kernel_params_mp_buf32[6] = 0;
              device_param->kernel_params_mp_buf32[7] = 0;
            }

            cl_int CL_err = CL_SUCCESS;

            for (uint i = 0; i < 3; i++) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_mp, i, sizeof (cl_mem),   (void *) device_param->kernel_params_mp[i]);
            for (uint i = 3; i < 4; i++) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_mp, i, sizeof (cl_ulong), (void *) device_param->kernel_params_mp[i]);
            for (uint i = 4; i < 8; i++) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_mp, i, sizeof (cl_uint),  (void *) device_param->kernel_params_mp[i]);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_root_css_buf,   CL_TRUE, 0, device_param->size_root_css,   root_css_buf,   0, NULL, NULL);
            CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_markov_css_buf, CL_TRUE, 0, device_param->size_markov_css, markov_css_buf, 0, NULL, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }
          }
        }
        else if (attack_mode == ATTACK_MODE_BF)
        {
          dictcnt = 0;  // number of "sub-masks", i.e. when using incremental mode

          if (increment)
          {
            for (uint i = 0; i < dictcnt; i++)
            {
              local_free (dictfiles[i]);
            }

            for (uint pw_len = MAX (1, pw_min); pw_len <= pw_max; pw_len++)
            {
              char *l1_filename = mp_get_truncated_mask (mask, strlen (mask), pw_len);

              if (l1_filename == NULL) break;

              dictcnt++;

              dictfiles[dictcnt - 1] = l1_filename;
            }
          }
          else
          {
            dictcnt++;

            dictfiles[dictcnt - 1] = mask;
          }

          if (dictcnt == 0)
          {
            log_error ("ERROR: Mask is too small");

            return -1;
          }
        }
      }

      free (induction_dictionaries);

      // induction_dictionaries_cnt = 0; // implied

      if (attack_mode != ATTACK_MODE_BF)
      {
        if (keyspace == 0)
        {
          induction_dictionaries = scan_directory (induction_directory);

          induction_dictionaries_cnt = count_dictionaries (induction_dictionaries);
        }
      }

      if (induction_dictionaries_cnt)
      {
        qsort (induction_dictionaries, induction_dictionaries_cnt, sizeof (char *), sort_by_mtime);
      }

      /**
       * prevent the user from using --skip/--limit together w/ maskfile and or dictfile
       */

      if (skip != 0 || limit != 0)
      {
        if ((maskcnt > 1) || (dictcnt > 1))
        {
          log_error ("ERROR: --skip/--limit are not supported with --increment or mask files");

          return -1;
        }
      }

      /**
       * prevent the user from using --keyspace together w/ maskfile and or dictfile
       */

      if (keyspace == 1)
      {
        if ((maskcnt > 1) || (dictcnt > 1))
        {
          log_error ("ERROR: --keyspace is not supported with --increment or mask files");

          return -1;
        }
      }

      for (uint dictpos = rd->dictpos; dictpos < dictcnt; dictpos++)
      {
        if (data.devices_status == STATUS_CRACKED) continue;
        if (data.devices_status == STATUS_ABORTED) continue;
        if (data.devices_status == STATUS_QUIT)    continue;

        rd->dictpos = dictpos;

        char *subid = logfile_generate_subid ();

        data.subid = subid;

        logfile_sub_msg ("START");

        if ((data.devices_status != STATUS_BYPASS) && (data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
        {
          data.devices_status = STATUS_INIT;
        }

        memset (data.words_progress_done,     0, data.salts_cnt * sizeof (u64));
        memset (data.words_progress_rejected, 0, data.salts_cnt * sizeof (u64));
        memset (data.words_progress_restored, 0, data.salts_cnt * sizeof (u64));

        memset (data.cpt_buf, 0, CPT_BUF * sizeof (cpt_t));

        data.cpt_pos = 0;

        data.cpt_start = time (NULL);

        data.cpt_total = 0;

        if (data.restore == 0)
        {
          rd->words_cur = skip;

          skip = 0;

          data.skip = 0;
        }

        data.ms_paused = 0;

        data.kernel_power_final = 0;

        data.words_cur = rd->words_cur;

        for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &data.devices_param[device_id];

          if (device_param->skipped) continue;

          device_param->speed_pos = 0;

          memset (device_param->speed_cnt, 0, SPEED_CACHE * sizeof (u64));
          memset (device_param->speed_ms,  0, SPEED_CACHE * sizeof (double));

          device_param->exec_pos = 0;

          memset (device_param->exec_ms, 0, EXEC_CACHE * sizeof (double));

          device_param->outerloop_pos  = 0;
          device_param->outerloop_left = 0;
          device_param->innerloop_pos  = 0;
          device_param->innerloop_left = 0;

          // some more resets:

          if (device_param->pws_buf) memset (device_param->pws_buf, 0, device_param->size_pws);

          device_param->pws_cnt = 0;

          device_param->words_off  = 0;
          device_param->words_done = 0;
        }

        // figure out some workload

        if (attack_mode == ATTACK_MODE_STRAIGHT)
        {
          if (data.wordlist_mode == WL_MODE_FILE)
          {
            char *dictfile = NULL;

            if (induction_dictionaries_cnt)
            {
              dictfile = induction_dictionaries[0];
            }
            else
            {
              dictfile = dictfiles[dictpos];
            }

            data.dictfile = dictfile;

            logfile_sub_string (dictfile);

            for (uint i = 0; i < rp_files_cnt; i++)
            {
              logfile_sub_var_string ("rulefile", rp_files[i]);
            }

            FILE *fd2 = fopen (dictfile, "rb");

            if (fd2 == NULL)
            {
              log_error ("ERROR: %s: %s", dictfile, strerror (errno));

              return -1;
            }

            data.words_cnt = count_words (wl_data, fd2, dictfile, dictstat_ctx);

            fclose (fd2);

            if (data.words_cnt == 0)
            {
              logfile_sub_msg ("STOP");

              continue;
            }
          }
        }
        else if (attack_mode == ATTACK_MODE_COMBI)
        {
          char *dictfile  = data.dictfile;
          char *dictfile2 = data.dictfile2;

          logfile_sub_string (dictfile);
          logfile_sub_string (dictfile2);

          if (data.combs_mode == COMBINATOR_MODE_BASE_LEFT)
          {
            FILE *fd2 = fopen (dictfile, "rb");

            if (fd2 == NULL)
            {
              log_error ("ERROR: %s: %s", dictfile, strerror (errno));

              return -1;
            }

            data.words_cnt = count_words (wl_data, fd2, dictfile, dictstat_ctx);

            fclose (fd2);
          }
          else if (data.combs_mode == COMBINATOR_MODE_BASE_RIGHT)
          {
            FILE *fd2 = fopen (dictfile2, "rb");

            if (fd2 == NULL)
            {
              log_error ("ERROR: %s: %s", dictfile2, strerror (errno));

              return -1;
            }

            data.words_cnt = count_words (wl_data, fd2, dictfile2, dictstat_ctx);

            fclose (fd2);
          }

          if (data.words_cnt == 0)
          {
            logfile_sub_msg ("STOP");

            continue;
          }
        }
        else if ((attack_mode == ATTACK_MODE_HYBRID1) || (attack_mode == ATTACK_MODE_HYBRID2))
        {
          char *dictfile = NULL;

          if (induction_dictionaries_cnt)
          {
            dictfile = induction_dictionaries[0];
          }
          else
          {
            dictfile = dictfiles[dictpos];
          }

          data.dictfile = dictfile;

          char *mask = data.mask;

          logfile_sub_string (dictfile);
          logfile_sub_string (mask);

          FILE *fd2 = fopen (dictfile, "rb");

          if (fd2 == NULL)
          {
            log_error ("ERROR: %s: %s", dictfile, strerror (errno));

            return -1;
          }

          data.words_cnt = count_words (wl_data, fd2, dictfile, dictstat_ctx);

          fclose (fd2);

          if (data.words_cnt == 0)
          {
            logfile_sub_msg ("STOP");

            continue;
          }
        }
        else if (attack_mode == ATTACK_MODE_BF)
        {
          local_free (css_buf);
          local_free (data.root_css_buf);
          local_free (data.markov_css_buf);

          char *mask = dictfiles[dictpos];

          logfile_sub_string (mask);

          // base

          css_buf = mp_gen_css (mask, strlen (mask), mp_sys, mp_usr, &css_cnt, hashconfig);

          if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
          {
            uint css_cnt_unicode = css_cnt * 2;

            cs_t *css_buf_unicode = (cs_t *) mycalloc (css_cnt_unicode, sizeof (cs_t));

            for (uint i = 0, j = 0; i < css_cnt; i += 1, j += 2)
            {
              memcpy (&css_buf_unicode[j + 0], &css_buf[i], sizeof (cs_t));

              css_buf_unicode[j + 1].cs_buf[0] = 0;
              css_buf_unicode[j + 1].cs_len    = 1;
            }

            free (css_buf);

            css_buf = css_buf_unicode;
            css_cnt = css_cnt_unicode;
          }

          // check if mask is not too large or too small for pw_min/pw_max  (*2 if unicode)

          uint mask_min = pw_min;
          uint mask_max = pw_max;

          if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
          {
            mask_min *= 2;
            mask_max *= 2;
          }

          if ((css_cnt < mask_min) || (css_cnt > mask_max))
          {
            if (css_cnt < mask_min)
            {
              log_info ("WARNING: Skipping mask '%s' because it is smaller than the minimum password length", mask);
            }

            if (css_cnt > mask_max)
            {
              log_info ("WARNING: Skipping mask '%s' because it is larger than the maximum password length", mask);
            }

            // skip to next mask

            logfile_sub_msg ("STOP");

            continue;
          }

          uint save_css_cnt = css_cnt;

          if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
          {
            if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
            {
              uint  salt_len = (uint)   data.salts_buf[0].salt_len;
              char *salt_buf = (char *) data.salts_buf[0].salt_buf;

              uint css_cnt_salt = css_cnt + salt_len;

              cs_t *css_buf_salt = (cs_t *) mycalloc (css_cnt_salt, sizeof (cs_t));

              memcpy (css_buf_salt, css_buf, css_cnt * sizeof (cs_t));

              for (uint i = 0, j = css_cnt; i < salt_len; i++, j++)
              {
                css_buf_salt[j].cs_buf[0] = salt_buf[i];
                css_buf_salt[j].cs_len    = 1;
              }

              free (css_buf);

              css_buf = css_buf_salt;
              css_cnt = css_cnt_salt;
            }
          }

          data.mask = mask;
          data.css_cnt = css_cnt;
          data.css_buf = css_buf;

          if (maskpos > 0 && dictpos == 0) free (masks[maskpos - 1]);

          uint uniq_tbls[SP_PW_MAX][CHARSIZ] = { { 0 } };

          mp_css_to_uniq_tbl (css_cnt, css_buf, uniq_tbls);

          if (root_table_buf   == NULL) root_table_buf   = (hcstat_table_t *) mycalloc (SP_ROOT_CNT,   sizeof (hcstat_table_t));
          if (markov_table_buf == NULL) markov_table_buf = (hcstat_table_t *) mycalloc (SP_MARKOV_CNT, sizeof (hcstat_table_t));

          sp_setup_tbl (shared_dir, markov_hcstat, markov_disable, markov_classic, root_table_buf, markov_table_buf);

          markov_threshold = (markov_threshold != 0) ? markov_threshold : CHARSIZ;

          cs_t *root_css_buf   = (cs_t *) mycalloc (SP_PW_MAX,           sizeof (cs_t));
          cs_t *markov_css_buf = (cs_t *) mycalloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

          data.root_css_buf   = root_css_buf;
          data.markov_css_buf = markov_css_buf;

          sp_tbl_to_css (root_table_buf, markov_table_buf, root_css_buf, markov_css_buf, markov_threshold, uniq_tbls);

          data.words_cnt = sp_get_sum (0, css_cnt, root_css_buf);

          local_free (root_table_buf);
          local_free (markov_table_buf);

          // copy + args

          uint css_cnt_l = css_cnt;
          uint css_cnt_r;

          if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
          {
            if (save_css_cnt < 6)
            {
              css_cnt_r = 1;
            }
            else if (save_css_cnt == 6)
            {
              css_cnt_r = 2;
            }
            else
            {
              if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
              {
                if (save_css_cnt == 8 || save_css_cnt == 10)
                {
                  css_cnt_r = 2;
                }
                else
                {
                  css_cnt_r = 4;
                }
              }
              else
              {
                if ((css_buf[0].cs_len * css_buf[1].cs_len * css_buf[2].cs_len) > 256)
                {
                  css_cnt_r = 3;
                }
                else
                {
                  css_cnt_r = 4;
                }
              }
            }
          }
          else
          {
            css_cnt_r = 1;

            /* unfinished code?
            int sum = css_buf[css_cnt_r - 1].cs_len;

            for (uint i = 1; i < 4 && i < css_cnt; i++)
            {
              if (sum > 1) break; // we really don't need alot of amplifier them for slow hashes

              css_cnt_r++;

              sum *= css_buf[css_cnt_r - 1].cs_len;
            }
            */
          }

          css_cnt_l -= css_cnt_r;

          data.bfs_cnt = sp_get_sum (0, css_cnt_r, root_css_buf);

          for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
          {
            hc_device_param_t *device_param = &data.devices_param[device_id];

            if (device_param->skipped) continue;

            device_param->kernel_params_mp_l[0] = &device_param->d_pws_buf;
            device_param->kernel_params_mp_l[1] = &device_param->d_root_css_buf;
            device_param->kernel_params_mp_l[2] = &device_param->d_markov_css_buf;

            device_param->kernel_params_mp_l_buf64[3] = 0;
            device_param->kernel_params_mp_l_buf32[4] = css_cnt_l;
            device_param->kernel_params_mp_l_buf32[5] = css_cnt_r;
            device_param->kernel_params_mp_l_buf32[6] = 0;
            device_param->kernel_params_mp_l_buf32[7] = 0;
            device_param->kernel_params_mp_l_buf32[8] = 0;

            if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)     device_param->kernel_params_mp_l_buf32[6] = full01;
            if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)     device_param->kernel_params_mp_l_buf32[6] = full80;
            if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS14) device_param->kernel_params_mp_l_buf32[7] = 1;
            if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS15) device_param->kernel_params_mp_l_buf32[8] = 1;

            device_param->kernel_params_mp_r[0] = &device_param->d_bfs;
            device_param->kernel_params_mp_r[1] = &device_param->d_root_css_buf;
            device_param->kernel_params_mp_r[2] = &device_param->d_markov_css_buf;

            device_param->kernel_params_mp_r_buf64[3] = 0;
            device_param->kernel_params_mp_r_buf32[4] = css_cnt_r;
            device_param->kernel_params_mp_r_buf32[5] = 0;
            device_param->kernel_params_mp_r_buf32[6] = 0;
            device_param->kernel_params_mp_r_buf32[7] = 0;

            cl_int CL_err = CL_SUCCESS;

            for (uint i = 0; i < 3; i++) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_mp_l, i, sizeof (cl_mem),   (void *) device_param->kernel_params_mp_l[i]);
            for (uint i = 3; i < 4; i++) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_mp_l, i, sizeof (cl_ulong), (void *) device_param->kernel_params_mp_l[i]);
            for (uint i = 4; i < 9; i++) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_mp_l, i, sizeof (cl_uint),  (void *) device_param->kernel_params_mp_l[i]);

            for (uint i = 0; i < 3; i++) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_mp_r, i, sizeof (cl_mem),   (void *) device_param->kernel_params_mp_r[i]);
            for (uint i = 3; i < 4; i++) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_mp_r, i, sizeof (cl_ulong), (void *) device_param->kernel_params_mp_r[i]);
            for (uint i = 4; i < 8; i++) CL_err |= hc_clSetKernelArg (data.ocl, device_param->kernel_mp_r, i, sizeof (cl_uint),  (void *) device_param->kernel_params_mp_r[i]);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }

            CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_root_css_buf,   CL_TRUE, 0, device_param->size_root_css,   root_css_buf,   0, NULL, NULL);
            CL_err |= hc_clEnqueueWriteBuffer (data.ocl, device_param->command_queue, device_param->d_markov_css_buf, CL_TRUE, 0, device_param->size_markov_css, markov_css_buf, 0, NULL, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }
          }
        }

        u64 words_base = data.words_cnt;

        if (data.attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (data.kernel_rules_cnt)
          {
            words_base /= data.kernel_rules_cnt;
          }
        }
        else if (data.attack_kern == ATTACK_KERN_COMBI)
        {
          if (data.combs_cnt)
          {
            words_base /= data.combs_cnt;
          }
        }
        else if (data.attack_kern == ATTACK_KERN_BF)
        {
          if (data.bfs_cnt)
          {
            words_base /= data.bfs_cnt;
          }
        }

        data.words_base = words_base;

        if (keyspace == 1)
        {
          log_info ("%" PRIu64 "", words_base);

          return 0;
        }

        if (data.words_cur > data.words_base)
        {
          log_error ("ERROR: Restore value greater keyspace");

          return -1;
        }

        if (data.words_cur)
        {
          if (data.attack_kern == ATTACK_KERN_STRAIGHT)
          {
            for (uint i = 0; i < data.salts_cnt; i++)
            {
              data.words_progress_restored[i] = data.words_cur * data.kernel_rules_cnt;
            }
          }
          else if (data.attack_kern == ATTACK_KERN_COMBI)
          {
            for (uint i = 0; i < data.salts_cnt; i++)
            {
              data.words_progress_restored[i] = data.words_cur * data.combs_cnt;
            }
          }
          else if (data.attack_kern == ATTACK_KERN_BF)
          {
            for (uint i = 0; i < data.salts_cnt; i++)
            {
              data.words_progress_restored[i] = data.words_cur * data.bfs_cnt;
            }
          }
        }

        /*
         * Update dictionary statistic
         */

        if (keyspace == 0)
        {
          dictstat_write (dictstat_ctx);
        }

        /**
         * Update loopback file
         */

        if (loopback == 1)
        {
          loopback_write_open (loopback_ctx, induction_directory);
        }

        /**
         * create autotune threads
         */

        hc_thread_t *c_threads = (hc_thread_t *) mycalloc (data.devices_cnt, sizeof (hc_thread_t));

        if ((data.devices_status != STATUS_BYPASS) && (data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
        {
          data.devices_status = STATUS_AUTOTUNE;
        }

        for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &devices_param[device_id];

          hc_thread_create (c_threads[device_id], thread_autotune, device_param);
        }

        hc_thread_wait (data.devices_cnt, c_threads);

        /*
         * Inform user about possible slow speeds
         */

        uint hardware_power_all = 0;

        uint kernel_power_all = 0;

        for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &devices_param[device_id];

          hardware_power_all += device_param->hardware_power;

          kernel_power_all += device_param->kernel_power;
        }

        data.hardware_power_all = hardware_power_all; // hardware_power_all is the same as kernel_power_all but without the influence of kernel_accel on the devices

        data.kernel_power_all = kernel_power_all;

        if ((wordlist_mode == WL_MODE_FILE) || (wordlist_mode == WL_MODE_MASK))
        {
          if (data.words_base < kernel_power_all)
          {
            if (quiet == 0)
            {
              clear_prompt ();

              log_info ("ATTENTION!");
              log_info ("  The wordlist or mask you are using is too small.");
              log_info ("  Therefore, hashcat is unable to utilize the full parallelization power of your device(s).");
              log_info ("  The cracking speed will drop.");
              log_info ("  Workaround: https://hashcat.net/wiki/doku.php?id=frequently_asked_questions#how_to_create_more_work_for_full_speed");
              log_info ("");
            }
          }
        }

        /**
         * create cracker threads
         */

        if ((data.devices_status != STATUS_BYPASS) && (data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
        {
          data.devices_status = STATUS_RUNNING;
        }

        if (initial_restore_done == 0)
        {
          if (data.restore_disable == 0) cycle_restore ();

          initial_restore_done = 1;
        }

        hc_timer_set (&data.timer_running);

        if ((wordlist_mode == WL_MODE_FILE) || (wordlist_mode == WL_MODE_MASK))
        {
          if ((quiet == 0) && (status == 0) && (benchmark == 0))
          {
            if (quiet == 0) send_prompt ();
          }
        }
        else if (wordlist_mode == WL_MODE_STDIN)
        {
          if (data.quiet == 0) log_info ("Starting attack in stdin mode...");
          if (data.quiet == 0) log_info ("");
        }

        time_t runtime_start;

        time (&runtime_start);

        data.runtime_start = runtime_start;

        data.prepare_time += runtime_start - prepare_start;

        for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &devices_param[device_id];

          if (wordlist_mode == WL_MODE_STDIN)
          {
            hc_thread_create (c_threads[device_id], thread_calc_stdin, device_param);
          }
          else
          {
            hc_thread_create (c_threads[device_id], thread_calc, device_param);
          }
        }

        hc_thread_wait (data.devices_cnt, c_threads);

        local_free (c_threads);

        if ((data.devices_status != STATUS_BYPASS) && (data.devices_status != STATUS_CRACKED) && (data.devices_status != STATUS_ABORTED) && (data.devices_status != STATUS_QUIT))
        {
          data.devices_status = STATUS_EXHAUSTED;
        }

        logfile_sub_var_uint ("status-after-work", data.devices_status);

        data.restore = 0;

        if (induction_dictionaries_cnt)
        {
          unlink (induction_dictionaries[0]);
        }

        free (induction_dictionaries);

        if (attack_mode != ATTACK_MODE_BF)
        {
          induction_dictionaries = scan_directory (induction_directory);

          induction_dictionaries_cnt = count_dictionaries (induction_dictionaries);
        }

        if (benchmark == 1)
        {
          status_benchmark ();

          if (machine_readable == 0)
          {
            log_info ("");
          }
        }
        else
        {
          if (quiet == 0)
          {
            clear_prompt ();

            log_info ("");

            status_display ();

            log_info ("");
          }
          else
          {
            if (status == 1)
            {
              status_display ();
            }
          }
        }

        if (induction_dictionaries_cnt)
        {
          qsort (induction_dictionaries, induction_dictionaries_cnt, sizeof (char *), sort_by_mtime);

          // yeah, this next statement is a little hack to make sure that --loopback runs correctly (because with it we guarantee that the loop iterates one more time)

          dictpos--;
        }

        /**
         * Update loopback file
         */

        if (loopback == 1)
        {
          loopback_write_close (loopback_ctx);
        }

        time_t runtime_stop;

        time (&runtime_stop);

        data.runtime_stop = runtime_stop;

        logfile_sub_uint (runtime_start);
        logfile_sub_uint (runtime_stop);

        time (&prepare_start);

        logfile_sub_msg ("STOP");

        global_free (subid);

        // from this point we handle bypass as running

        if (data.devices_status == STATUS_BYPASS)
        {
          data.devices_status = STATUS_RUNNING;
        }

        // and overwrite benchmark aborts as well

        if (data.benchmark == 1)
        {
          if (data.devices_status == STATUS_ABORTED)
          {
            data.devices_status = STATUS_RUNNING;
          }
        }

        // finalize task

        if (data.devices_status == STATUS_CRACKED) break;
        if (data.devices_status == STATUS_ABORTED) break;
        if (data.devices_status == STATUS_QUIT)    break;
      }

      if (data.devices_status == STATUS_CRACKED) break;
      if (data.devices_status == STATUS_ABORTED) break;
      if (data.devices_status == STATUS_QUIT)    break;
    }

    // problems could occur if already at startup everything was cracked (because of .pot file reading etc), we must set some variables here to avoid NULL pointers
    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (data.wordlist_mode == WL_MODE_FILE)
      {
        if (data.dictfile == NULL)
        {
          if (dictfiles != NULL)
          {
            data.dictfile = dictfiles[0];

            hc_timer_set (&data.timer_running);
          }
        }
      }
    }
    // NOTE: combi is okay because it is already set beforehand
    else if (attack_mode == ATTACK_MODE_HYBRID1 || attack_mode == ATTACK_MODE_HYBRID2)
    {
      if (data.dictfile == NULL)
      {
        if (dictfiles != NULL)
        {
          hc_timer_set (&data.timer_running);

          data.dictfile = dictfiles[0];
        }
      }
    }
    else if (attack_mode == ATTACK_MODE_BF)
    {
      if (data.mask == NULL)
      {
        hc_timer_set (&data.timer_running);

        data.mask = masks[0];
      }
    }

    // if cracked / aborted remove last induction dictionary

    for (int file_pos = 0; file_pos < induction_dictionaries_cnt; file_pos++)
    {
      struct stat induct_stat;

      if (stat (induction_dictionaries[file_pos], &induct_stat) == 0)
      {
        unlink (induction_dictionaries[file_pos]);
      }
    }

    // wait for inner threads

    data.shutdown_inner = 1;

    for (uint thread_idx = 0; thread_idx < inner_threads_cnt; thread_idx++)
    {
      hc_thread_wait (1, &inner_threads[thread_idx]);
    }

    local_free (inner_threads);

    // we dont need restore file anymore
    if (data.restore_disable == 0)
    {
      if ((data.devices_status == STATUS_EXHAUSTED) || (data.devices_status == STATUS_CRACKED))
      {
        unlink (eff_restore_file);
        unlink (new_restore_file);
      }
      else
      {
        cycle_restore ();
      }
    }

    // finally save left hashes

    if ((hashlist_mode == HL_MODE_FILE) && (remove == 1) && (data.digests_saved != data.digests_done))
    {
      save_hash ();
    }

    /**
     * Clean up
     */

    for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &data.devices_param[device_id];

      if (device_param->skipped) continue;

      cl_int CL_err = CL_SUCCESS;

      local_free (device_param->combs_buf);
      local_free (device_param->hooks_buf);
      local_free (device_param->device_name);
      local_free (device_param->device_name_chksum);
      local_free (device_param->device_version);
      local_free (device_param->driver_version);

      if (device_param->pws_buf)            myfree (device_param->pws_buf);

      if (device_param->d_pws_buf)          CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_pws_buf);
      if (device_param->d_pws_amp_buf)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_pws_amp_buf);
      if (device_param->d_rules)            CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_rules);
      if (device_param->d_rules_c)          CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_rules_c);
      if (device_param->d_combs)            CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_combs);
      if (device_param->d_combs_c)          CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_combs_c);
      if (device_param->d_bfs)              CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bfs);
      if (device_param->d_bfs_c)            CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bfs_c);
      if (device_param->d_bitmap_s1_a)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bitmap_s1_a);
      if (device_param->d_bitmap_s1_b)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bitmap_s1_b);
      if (device_param->d_bitmap_s1_c)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bitmap_s1_c);
      if (device_param->d_bitmap_s1_d)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bitmap_s1_d);
      if (device_param->d_bitmap_s2_a)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bitmap_s2_a);
      if (device_param->d_bitmap_s2_b)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bitmap_s2_b);
      if (device_param->d_bitmap_s2_c)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bitmap_s2_c);
      if (device_param->d_bitmap_s2_d)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_bitmap_s2_d);
      if (device_param->d_plain_bufs)       CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_plain_bufs);
      if (device_param->d_digests_buf)      CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_digests_buf);
      if (device_param->d_digests_shown)    CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_digests_shown);
      if (device_param->d_salt_bufs)        CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_salt_bufs);
      if (device_param->d_esalt_bufs)       CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_esalt_bufs);
      if (device_param->d_tmps)             CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_tmps);
      if (device_param->d_hooks)            CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_hooks);
      if (device_param->d_result)           CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_result);
      if (device_param->d_scryptV0_buf)     CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_scryptV0_buf);
      if (device_param->d_scryptV1_buf)     CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_scryptV1_buf);
      if (device_param->d_scryptV2_buf)     CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_scryptV2_buf);
      if (device_param->d_scryptV3_buf)     CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_scryptV3_buf);
      if (device_param->d_root_css_buf)     CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_root_css_buf);
      if (device_param->d_markov_css_buf)   CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_markov_css_buf);
      if (device_param->d_tm_c)             CL_err |= hc_clReleaseMemObject (data.ocl, device_param->d_tm_c);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clReleaseMemObject(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (device_param->kernel1)        CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel1);
      if (device_param->kernel12)       CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel12);
      if (device_param->kernel2)        CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel2);
      if (device_param->kernel23)       CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel23);
      if (device_param->kernel3)        CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel3);
      if (device_param->kernel_mp)      CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel_mp);
      if (device_param->kernel_mp_l)    CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel_mp_l);
      if (device_param->kernel_mp_r)    CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel_mp_r);
      if (device_param->kernel_tm)      CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel_tm);
      if (device_param->kernel_amp)     CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel_amp);
      if (device_param->kernel_memset)  CL_err |= hc_clReleaseKernel (data.ocl, device_param->kernel_memset);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clReleaseKernel(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (device_param->program)     CL_err |= hc_clReleaseProgram (data.ocl, device_param->program);
      if (device_param->program_mp)  CL_err |= hc_clReleaseProgram (data.ocl, device_param->program_mp);
      if (device_param->program_amp) CL_err |= hc_clReleaseProgram (data.ocl, device_param->program_amp);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clReleaseProgram(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (device_param->command_queue) CL_err |= hc_clReleaseCommandQueue (data.ocl, device_param->command_queue);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clReleaseCommandQueue(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (device_param->context) CL_err |= hc_clReleaseContext (data.ocl, device_param->context);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: hc_clReleaseContext(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }
    }

    // reset default fan speed

    #if defined (HAVE_HWMON)
    if (gpu_temp_disable == 0)
    {
      if (gpu_temp_retain != 0)
      {
        hc_thread_mutex_lock (mux_hwmon);

        for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
        {
          hc_device_param_t *device_param = &data.devices_param[device_id];

          if (device_param->skipped) continue;

          if (data.hm_device[device_id].fan_set_supported == 1)
          {
            int rc = -1;

            if (device_param->device_vendor_id == VENDOR_ID_AMD)
            {
              rc = hm_set_fanspeed_with_device_id_adl (device_id, 100, 0);
            }
            else if (device_param->device_vendor_id == VENDOR_ID_NV)
            {
              #if defined (__linux__)
              rc = set_fan_control (data.hm_xnvctrl, data.hm_device[device_id].xnvctrl, NV_CTRL_GPU_COOLER_MANUAL_CONTROL_FALSE);
              #endif

              #if defined (_WIN)
              rc = hm_set_fanspeed_with_device_id_nvapi (device_id, 100, 0);
              #endif
            }

            if (rc == -1) log_info ("WARNING: Failed to restore default fan speed and policy for device #%", device_id + 1);
          }
        }

        hc_thread_mutex_unlock (mux_hwmon);
      }
    }

    // reset power tuning

    if (powertune_enable == 1)
    {
      hc_thread_mutex_lock (mux_hwmon);

      for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &data.devices_param[device_id];

        if (device_param->skipped) continue;

        if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_AMD)
        {
          if (data.hm_device[device_id].od_version == 6)
          {
            // check powertune capabilities first, if not available then skip device

            int powertune_supported = 0;

            if ((hm_ADL_Overdrive6_PowerControl_Caps (data.hm_adl, data.hm_device[device_id].adl, &powertune_supported)) != ADL_OK)
            {
              log_error ("ERROR: Failed to get ADL PowerControl Capabilities");

              return -1;
            }

            if (powertune_supported != 0)
            {
              // powercontrol settings

              if ((hm_ADL_Overdrive_PowerControl_Set (data.hm_adl, data.hm_device[device_id].adl, od_power_control_status[device_id])) != ADL_OK)
              {
                log_info ("ERROR: Failed to restore the ADL PowerControl values");

                return -1;
              }

              // clocks

              ADLOD6StateInfo *performance_state = (ADLOD6StateInfo*) mycalloc (1, sizeof (ADLOD6StateInfo) + sizeof (ADLOD6PerformanceLevel));

              performance_state->iNumberOfPerformanceLevels = 2;

              performance_state->aLevels[0].iEngineClock = od_clock_mem_status[device_id].state.aLevels[0].iEngineClock;
              performance_state->aLevels[1].iEngineClock = od_clock_mem_status[device_id].state.aLevels[1].iEngineClock;
              performance_state->aLevels[0].iMemoryClock = od_clock_mem_status[device_id].state.aLevels[0].iMemoryClock;
              performance_state->aLevels[1].iMemoryClock = od_clock_mem_status[device_id].state.aLevels[1].iMemoryClock;

              if ((hm_ADL_Overdrive_State_Set (data.hm_adl, data.hm_device[device_id].adl, ADL_OD6_SETSTATE_PERFORMANCE, performance_state)) != ADL_OK)
              {
                log_info ("ERROR: Failed to restore ADL performance state");

                return -1;
              }

              local_free (performance_state);
            }
          }
        }

        if (data.devices_param[device_id].device_vendor_id == VENDOR_ID_NV)
        {
          unsigned int limit = nvml_power_limit[device_id];

          if (limit > 0)
          {
            hm_NVML_nvmlDeviceSetPowerManagementLimit (data.hm_nvml, 0, data.hm_device[device_id].nvml, limit);
          }
        }
      }

      hc_thread_mutex_unlock (mux_hwmon);
    }

    if (gpu_temp_disable == 0)
    {
      if (data.hm_nvml)
      {
        hm_NVML_nvmlShutdown (data.hm_nvml);

        nvml_close (data.hm_nvml);

        data.hm_nvml = NULL;
      }

      if (data.hm_nvapi)
      {
        hm_NvAPI_Unload (data.hm_nvapi);

        nvapi_close (data.hm_nvapi);

        data.hm_nvapi = NULL;
      }

      if (data.hm_xnvctrl)
      {
        hm_XNVCTRL_XCloseDisplay (data.hm_xnvctrl);

        xnvctrl_close (data.hm_xnvctrl);

        data.hm_xnvctrl = NULL;
      }

      if (data.hm_adl)
      {
        hm_ADL_Main_Control_Destroy (data.hm_adl);

        adl_close (data.hm_adl);

        data.hm_adl = NULL;
      }
    }
    #endif // HAVE_HWMON

    // free memory

    local_free (masks);

    outfile_destroy (outfile_ctx);

    potfile_write_close (potfile_ctx);

    potfile_destroy (potfile_ctx);

    dictstat_destroy (dictstat_ctx);

    loopback_destroy (loopback_ctx);

    local_free (all_kernel_rules_cnt);
    local_free (all_kernel_rules_buf);

    local_free (wl_data->buf);
    local_free (wl_data);

    local_free (bitmap_s1_a);
    local_free (bitmap_s1_b);
    local_free (bitmap_s1_c);
    local_free (bitmap_s1_d);
    local_free (bitmap_s2_a);
    local_free (bitmap_s2_b);
    local_free (bitmap_s2_c);
    local_free (bitmap_s2_d);

    #if defined (HAVE_HWMON)
    local_free (od_clock_mem_status);
    local_free (od_power_control_status);
    local_free (nvml_power_limit);
    #endif

    global_free (devices_param);

    global_free (kernel_rules_buf);

    global_free (root_css_buf);
    global_free (markov_css_buf);

    global_free (digests_buf);
    global_free (digests_shown);
    global_free (digests_shown_tmp);

    global_free (salts_buf);
    global_free (salts_shown);

    global_free (esalts_buf);

    global_free (words_progress_done);
    global_free (words_progress_rejected);
    global_free (words_progress_restored);

    if (data.devices_status == STATUS_QUIT) break;
  }

  // wait for outer threads

  data.shutdown_outer = 1;

  for (uint thread_idx = 0; thread_idx < outer_threads_cnt; thread_idx++)
  {
    hc_thread_wait (1, &outer_threads[thread_idx]);
  }

  local_free (outer_threads);

  // destroy others mutex

  hc_thread_mutex_delete (mux_dispatcher);
  hc_thread_mutex_delete (mux_counter);
  hc_thread_mutex_delete (mux_display);
  hc_thread_mutex_delete (mux_hwmon);

  // free memory

  local_free (hashconfig);

  local_free (eff_restore_file);
  local_free (new_restore_file);

  local_free (rd);

  // tuning db

  tuning_db_destroy (tuning_db);

  // induction directory

  if (induction_dir == NULL)
  {
    if (attack_mode != ATTACK_MODE_BF)
    {
      if (rmdir (induction_directory) == -1)
      {
        if (errno == ENOENT)
        {
          // good, we can ignore
        }
        else if (errno == ENOTEMPTY)
        {
          // good, we can ignore
        }
        else
        {
          log_error ("ERROR: %s: %s", induction_directory, strerror (errno));

          return -1;
        }
      }

      local_free (induction_directory);
    }
  }

  // outfile-check directory

  if (outfile_check_dir == NULL)
  {
    if (rmdir (outfile_check_directory) == -1)
    {
      if (errno == ENOENT)
      {
        // good, we can ignore
      }
      else if (errno == ENOTEMPTY)
      {
        // good, we can ignore
      }
      else
      {
        log_error ("ERROR: %s: %s", outfile_check_directory, strerror (errno));

        return -1;
      }
    }

    local_free (outfile_check_directory);
  }

  time_t proc_stop;

  time (&proc_stop);

  logfile_top_uint (proc_start);
  logfile_top_uint (proc_stop);

  logfile_top_msg ("STOP");

  if (quiet == 0) log_info_nn ("Started: %s", ctime (&proc_start));
  if (quiet == 0) log_info_nn ("Stopped: %s", ctime (&proc_stop));

  if (data.ocl) ocl_close (data.ocl);

  if (data.devices_status == STATUS_ABORTED)            return 2;
  if (data.devices_status == STATUS_QUIT)               return 2;
  if (data.devices_status == STATUS_STOP_AT_CHECKPOINT) return 2;
  if (data.devices_status == STATUS_EXHAUSTED)          return 1;
  if (data.devices_status == STATUS_CRACKED)            return 0;

  return -1;
}
