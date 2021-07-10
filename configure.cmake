include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckLinkerFlag OPTIONAL)
include(TestBigEndian)
########################################
macro(check_include_file_def incfile var)
  check_include_file("${incfile}" ${var})
  if(${var})
    list(APPEND pvtDefs ${var}=1)
  endif()
endmacro()
macro(check_compiles_def var src)
  check_c_source_compiles("${src}" ${var})
  if(${var})
    list(APPEND pvtDefs ${var}=1)
  endif()
endmacro()
macro(check_compiler_opt)
  foreach(opt ${ARGN})
    string(REPLACE "-" "_" opt_ ${opt})
    string(REPLACE "=" "_" opt_ ${opt_})
    check_c_compiler_flag("${opt}" has_na_c${opt_})
    if(has_na_c${opt_})
      list(APPEND pvtOpts ${opt})
    endif()
  endforeach()
endmacro()
macro(check_link_opts)
  if(COMMAND check_linker_flag) # new in cmake 3.18
    foreach(opt ${ARGN})
      string(REPLACE "-" "_" opt_ ${opt})
      string(REPLACE "," "_" opt_ ${opt_})
      check_linker_flag(C "${opt}" has_na_ln${opt_})
      if(has_na_ln${opt_})
        list(APPEND linkOpts ${opt})
      endif()
    endforeach()
  endif()
endmacro()
macro(check_func_exists_def func def)
  check_function_exists(${func} ${def})
  if(${def})
    list(APPEND pvtDefs ${def}=1)
  endif()
endmacro()
########################################
test_big_endian(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
  list(APPEND pvtDefs NATIVE_BIG_ENDIAN)
else()
  list(APPEND pvtDefs NATIVE_LITTLE_ENDIAN)
endif()
########################################
if(ENABLE_BLOCKING_RANDOM)
  list(APPEND pvtDefs USE_BLOCKING_RANDOM=1)
endif()
if(ENABLE_MINIMAL)
  list(APPEND pvtDefs MINIMAL=1)
endif()
########################################
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads)
if(CMAKE_USE_PTHREADS_INIT)
  list(APPEND pvtDefs HAVE_PTHREAD=1)
endif()
########################################
check_compiles_def(HAVE_LIBCTGRIND "
/* Override any GCC internal prototype to avoid an error.
   Use char because int might match the return type of a GCC
   builtin and then its argument prototype would still apply.  */
char ct_poison ();
int main(void)
{
  return ct_poison ();
  return 0;
}
" )
check_compiles_def(HAVE_C_VARARRAYS "
/* Test for VLA support.  This test is partly inspired
   from examples in the C standard.  Use at least two VLA
   functions to detect the GCC 3.4.3 bug described in:
   https://lists.gnu.org/archive/html/bug-gnulib/2014-08/msg00014.html
*/
#ifdef __STDC_NO_VLA__
  syntax error;
#else
  extern int n;
  int B[100];
  int fvla(int m, int C[m][m]);
  int simple(int count, int all[static count])
  {
    return all[count - 1];
  }
  int fvla(int m, int C[m][m])
  {
    typedef int VLA[m][m];
    VLA x;
    int D[m];
    static int (*q)[m] = &B;
    int (*s)[n] = q;
    return C && &x[0][0] == &D[0] && &D[0] == s[0];
  }
#endif
int main(void)
{
  return 0;
}
" )
if(NOT HAVE_C_VARARRAYS)
  list(APPEND pvtDefs __STDC_NO_VLA__=1)
endif()
check_compiles_def(HAVE_CATCHABLE_SEGV "
#include <signal.h>
#include <stdlib.h>
static void sig(int _) { exit(0); }
int main(void)
{
  volatile unsigned char * volatile x = (volatile unsigned char *) malloc(8);
  size_t i;
  signal(SIGSEGV, sig);
  signal(SIGBUS, sig);
#if !defined(__SANITIZE_ADDRESS__) && !defined(__EMSCRIPTEN__)
  for (i = 0; i < 10000000; i += 1024) { x[-i] = x[i] = (unsigned char) i; }
#endif
  free((void *) x);
  exit(1)
  return 0;
}
" )
check_compiles_def(HAVE_CATCHABLE_ABRT "
#include <signal.h>
#include <stdlib.h>
#ifndef SIGABRT
# error SIGABRT is not defined
#endif
static void sigabrt_handler_3(int _)
{
  exit(0);
}
static void sigabrt_handler_2(int _)
{
  signal(SIGABRT, sigabrt_handler_3);
  abort();
  exit(1);
}
static void sigabrt_handler_1(int _)
{
  signal(SIGABRT, sigabrt_handler_2);
  abort();
  exit(1);
}
int main(void)
{
  signal(SIGABRT, sigabrt_handler_1);
  abort();
  exit(1);
  return 0;
}
" )
########################################
# TLS
set(tls_keywords
  thread_local
  _Thread_local
  __thread
  "__declspec(thread)"
  )
set(idx 0)
foreach(tls_keyword ${tls_keywords})
  check_c_source_compiles( "
#include <stdlib.h>
int main(void)
{
  static ${tls_keyword} int bar;
  return 0;
}
"   TLS_${idx}
    )
  if(TLS_${idx})
    list(APPEND pvtDefs TLS=${tls_keyword})
    check_compiler_opt(-ftls-model=local-dynamic)
    break()
  endif()
  math(EXPR idx "${idx}+1")
endforeach()
########################################
check_compiles_def(HAVE_MMINTRIN_H "
#pragma GCC target(\"mmx\")
#include <mmintrin.h>
int main(void)
{
  __m64 x = _mm_setzero_si64();
  return 0;
}
" )
if(HAVE_MMINTRIN_H)
  check_compiler_opt(-mmmx)
endif()
check_compiles_def(HAVE_EMMINTRIN_H "
#pragma GCC target(\"sse2\")
#ifndef __SSE2__
# define __SSE2__
#endif
#include <emmintrin.h>
int main(void)
{
  __m128d x = _mm_setzero_pd();
  __m128i z = _mm_srli_epi64(_mm_setzero_si128(), 26);
  return 0;
}
" )
if(HAVE_EMMINTRIN_H)
  check_compiler_opt(-msse2)
endif()
check_compiles_def(HAVE_PMMINTRIN_H "
#pragma GCC target(\"sse3\")
#include <pmmintrin.h>
int main(void)
{
  __m128 x = _mm_addsub_ps(_mm_cvtpd_ps(_mm_setzero_pd()), _mm_cvtpd_ps(_mm_setzero_pd()));
  return 0;
}
" )
if(HAVE_PMMINTRIN_H)
  check_compiler_opt(-msse3)
endif()
check_compiles_def(HAVE_TMMINTRIN_H "
#pragma GCC target(\"ssse3\")
#include <tmmintrin.h>
int main(void)
{
  __m64 x = _mm_abs_pi32(_m_from_int(0));
  return 0;
}
" )
if(HAVE_TMMINTRIN_H)
  check_compiler_opt(-mssse3)
endif()
check_compiles_def(HAVE_SMMINTRIN_H "
#pragma GCC target(\"sse4.1\")
#include <smmintrin.h>
int main(void)
{
  __m128i x = _mm_minpos_epu16(_mm_setzero_si128());
  return 0;
}
" )
if(HAVE_SMMINTRIN_H)
  check_compiler_opt(-msse4.1)
endif()
check_compiles_def(HAVE_AVXINTRIN_H "
#ifdef __native_client__
# error NativeClient detected - Avoiding AVX opcodes
#endif
#pragma GCC target(\"avx\")
#include <immintrin.h>
int main(void)
{
  _mm256_zeroall();
  return 0;
}
" )
if(HAVE_AVXINTRIN_H)
  check_compiler_opt(-mavx)
endif()
check_compiles_def(HAVE_AVX2INTRIN_H "
#ifdef __native_client__
# error NativeClient detected - Avoiding AVX2 opcodes
#endif
#pragma GCC target(\"avx2\")
#include <immintrin.h>
int main(void)
{
  __m256 x = _mm256_set1_ps(3.14);
  __m256 y = _mm256_permutevar8x32_ps(x, _mm256_set1_epi32(42));
  return _mm256_movemask_ps(_mm256_cmp_ps(x, y, _CMP_NEQ_OQ));
}
" )
if(HAVE_AVX2INTRIN_H)
  check_compiler_opt(-mavx2)
endif()
########################################
# _mm256_broadcastsi128_si256_DEFINED
check_c_source_compiles("
#ifdef __native_client__
# error NativeClient detected - Avoiding AVX2 opcodes
#endif
#pragma GCC target(\"avx2\")
#include <immintrin.h>
int main(void)
{
  __m256i y = _mm256_broadcastsi128_si256(_mm_setzero_si128());
  return 0;
}
" _mm256_broadcastsi128_si256_DEFINED
  )
if(NOT _mm256_broadcastsi128_si256_DEFINED)
  list(APPEND pvtDefs _mm256_broadcastsi128_si256=_mm_broadcastsi128_256)
endif()
########################################
check_compiles_def(HAVE_AVX512FINTRIN_H "
#ifdef __native_client__
# error NativeClient detected - Avoiding AVX512F opcodes
#endif
#pragma GCC target(\"avx512f\")
#include <immintrin.h>
#ifndef __AVX512F__
# error No AVX512 support
#elif defined(__clang__)
# if __clang_major__ < 4
#  error Compiler AVX512 support may be broken
# endif
#elif defined(__GNUC__)
# if __GNUC__ < 6
#  error Compiler AVX512 support may be broken
# endif
#endif
int main(void)
{
  __m512i x = _mm512_setzero_epi32();
  __m512i y = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7), x);
  return 0;
}
" )
if(HAVE_AVX512FINTRIN_H)
  check_compiler_opt(-mavx512f)
else()
  check_compiler_opt(-mno-avx512f)
endif()
check_compiles_def(HAVE_WMMINTRIN_H "
#ifdef __native_client__
# error NativeClient detected - Avoiding AESNI opcodes
#endif
#pragma GCC target(\"aes\")
#pragma GCC target(\"pclmul\")
#include <wmmintrin.h>
int main(void)
{
  __m128i x = _mm_aesimc_si128(_mm_setzero_si128());
  __m128i y = _mm_clmulepi64_si128(_mm_setzero_si128(), _mm_setzero_si128(), 0);
  return 0;
}
" )
if(HAVE_WMMINTRIN_H)
  check_compiler_opt(-maes -mpclmul)
endif()
########################################
check_compiles_def(HAVE_RDRAND "
#ifdef __native_client__
# error NativeClient detected - Avoiding RDRAND opcodes
#endif
pragma GCC target(\"rdrnd\")
#include <immintrin.h>
int main(void)
{
  unsigned long long x;
  _rdrand64_step(&x);
  return 0;
}
" )
if(HAVE_RDRAND)
  check_compiler_opt(-mrdrnd)
endif()
########################################
check_include_file_def(sys/mman.h HAVE_SYS_MMAN_H)
check_include_file_def(sys/random.h HAVE_SYS_RANDOM_H)
check_include_file_def(intrin.h HAVE_INTRIN_H)
########################################
check_compiles_def(HAVE__XGETBV "
#include <intrin.h>
int main(void)
{
  (void) _xgetbv(0);
  return 0;
}
" )
check_compiles_def(HAVE_INLINE_ASM "
int main(void)
{
  int a = 42;
  int *pnt = &a;
  __asm__ __volatile__ (\"\" : : \"r\"(pnt) : \"memory\");
  return 0;
}
" )
check_compiles_def(HAVE_AMD64_ASM "
int main(void)
{
#if defined(__amd64) || defined(__amd64__) || defined(__x86_64__)
# if defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__) || defined(_WIN32) || defined(_WIN64)
#  error Windows x86_64 calling conventions are not supported yet
# endif
/* neat */
#else
# error !x86_64
#endif
  unsigned char i = 0, o = 0, t;
  __asm__ __volatile__ (\"pxor %%xmm12, %%xmm6 \n\"
    \"movb (%[i]), %[t] \n\"
    \"addb %[t], (%[o]) \n\"
    : [t] \"=&r\"(t)
    : [o] \"D\"(&o), [i] \"S\"(&i)
    : \"memory\", \"flags\", \"cc\");
  return 0;
}
" )
check_compiles_def(HAVE_AVX_ASM "
int main(void)
{
#if defined(__amd64) || defined(__amd64__) || defined(__x86_64__)
# if defined(__CYGWIN__) || defined(__MINGW32__) || defined(__MINGW64__) || defined(_WIN32) || defined(_WIN64)
#  error Windows x86_64 calling conventions are not supported yet
# endif
/* neat */
#else
# error !x86_64
#endif
  __asm__ __volatile__ (\"vpunpcklqdq %xmm0,%xmm13,%xmm0\");
  return 0;
}
" )
check_compiles_def(HAVE_TI_MODE "
#if !defined(__clang__) && !defined(__GNUC__) && !defined(__SIZEOF_INT128__)
# error mode(TI) is a gcc extension, and __int128 is not available
#endif
#if defined(__clang__) && !defined(__x86_64__) && !defined(__aarch64__)
# error clang does not properly handle the 128-bit type on 32-bit systems
#endif
#ifndef NATIVE_LITTLE_ENDIAN
# error libsodium currently expects a little endian CPU for the 128-bit type
#endif
#ifdef __EMSCRIPTEN__
# error emscripten currently doesn't support some operations on integers larger than 64 bits
#endif
#include <stddef.h>
#include <stdint.h>
#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 uint128_t;
#else
typedef unsigned uint128_t __attribute__((mode(TI)));
#endif
void fcontract(uint128_t *t)
{
  *t += 0x8000000000000 - 1;
  *t *= *t;
  *t >>= 84;
}
int main(void)
{
  (void) fcontract;
  return 0;
}
" )
check_compiles_def(HAVE_CPUID "
int main(void)
{
  unsigned int cpu_info[4];
  __asm__ __volatile__ (\"xchgl %%ebx, %k1; cpuid; xchgl %%ebx, %k1\" :
    \"=a\" (cpu_info[0]), \"=&r\" (cpu_info[1]),
    \"=c\" (cpu_info[2]), \"=d\" (cpu_info[3]) :
    \"0\" (0U), \"2\" (0U));
  return 0;
}
" )
########################################
# ASM_HIDE_SYMBOL
check_c_source_compiles("
int main(void)
{
  __asm__ __volatile__ (\".hidden dummy_symbol \n\"
                        \".hidden _dummy_symbol \n\"
                        \".globl dummy_symbol \n\"
                        \".globl _dummy_symbol \n\"
                        \"dummy_symbol: \n\"
                        \"_dummy_symbol: \n\"
                        \"    nop \n\"
                       );
  return 0;
}
" ASM_HIDE_SYMBOL
  )
if(ASM_HIDE_SYMBOL)
  list(APPEND pvtDefs ASM_HIDE_SYMBOL=.hidden)
endif()
########################################
check_compiles_def(HAVE_WEAK_SYMBOLS "
#if !defined(__ELF__) && !defined(__APPLE_CC__)
# error Support for weak symbols may not be available
#endif
__attribute__((weak)) void __dummy(void *x) { }
void f(void *x) { __dummy(x); }
int main(void)
{
  return 0;
}
" )
check_compiles_def(HAVE_ATOMIC_OPS "
int main(void)
{
  static volatile int _sodium_lock;
  __sync_lock_test_and_set(&_sodium_lock, 1);
  __sync_lock_release(&_sodium_lock);
  return 0;
}
" )
check_compiles_def(HAVE_ALLOCA_H "
#include <alloca.h>
int main(void)
{
  char *p = (char *) alloca (2 * sizeof (int));
  if (p) return 0;
  return 0;
}
" )
check_compiles_def(HAVE_ALLOCA "
#include <stdlib.h>
#include <stddef.h>
#ifndef alloca
# ifdef __GNUC__
#  define alloca __builtin_alloca
# elif defined _MSC_VER
#  include <malloc.h>
#  define alloca _alloca
# else
#  ifdef  __cplusplus
extern \"C\"
#  endif
void *alloca (size_t);
# endif
#endif
int main(void)
{
  char *p = (char *) alloca (1);
  if (p) return 0;
  return 0;
}
" )
########################################
check_func_exists_def(arc4random HAVE_ARC4RANDOM)
check_func_exists_def(mmap HAVE_MMAP)
check_func_exists_def(mlock HAVE_MLOCK)
check_func_exists_def(madvise HAVE_MADVISE)
check_func_exists_def(mprotect HAVE_MPROTECT)
########################################
check_compiles_def(HAVE_GETRANDOM "
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif
#ifdef __SANITIZE_ADDRESS__
# error A recent libasan version on an old system may intercept nonexistent functions
#endif
int main(void)
{
  unsigned char buf;
  (void) getrandom((void *) &buf, 1U, 0U);
  return 0;
}
" )
check_compiles_def(HAVE_GETENTROPY "
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_SYS_RANDOM_H
# include <sys/random.h>
#endif
#ifdef __SANITIZE_ADDRESS__
# error A recent libasan version on an old system may intercept nonexistent functions
#endif
int main(void)
{
  unsigned char buf;
  if (&getentropy != NULL) {
    (void) getentropy((void *) &buf, 1U);
  }
  return 0;
}
" )
check_compiles_def(HAVE_GETPID "
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
  pid_t pid = getpid();
  return 0;
}
" )
########################################
check_func_exists_def(posix_memalign HAVE_POSIX_MEMALIGN)
check_func_exists_def(nanosleep HAVE_NANOSLEEP)
check_func_exists_def(memset_s HAVE_MEMSET_S)
check_func_exists_def(explicit_bzero HAVE_EXPLICIT_BZERO)
check_func_exists_def(explicit_memset HAVE_EXPLICIT_MEMSET)
########################################
check_compiler_opt(
  -fvisibility=hidden
  -fPIC
  -fno-strict-aliasing
  -fno-strict-overflow
  -fstack-protector
  -flax-vector-conversions
  -Wall
  -Wextra
  -Wbad-function-cast
  -Wcast-qual
  -Wdiv-by-zero
  -Wduplicated-branches
  -Wduplicated-cond
  -Wfloat-equal
  -Wformat=2
  -Wlogical-op
  -Wmaybe-uninitialized
  -Wmisleading-indentation
  -Wmissing-declarations
  -Wmissing-prototypes
  -Wnested-externs
  -Wno-type-limits
  -Wno-unknown-pragmas
  -Wnormalized=id
  -Wnull-dereference
  -Wold-style-declaration
  -Wpointer-arith
  -Wredundant-decls
  -Wrestrict
  -Wshorten-64-to-32
  -Wsometimes-uninitialized
  -Wstrict-prototypes
  -Wswitch-enum
  -Wvariable-decl
  -Wwrite-strings
  )
if(MSVC)
  list(REMOVE_ITEM pvtOpts
    -Wall # too many warnings
    )
endif()
########################################
check_link_opts(
  # populates linkOpts...
  # TODO target_link_options() cannot be used to
  # add options for static library targets
  "-fstack-protector"
  "-Wl,-z,relro"
  "-Wl,-z,now"
  "-Wl,-z,noexecstack"
  )
########################################
list(APPEND pvtDefs CONFIGURED)
########################################
if(VERBOSE_DEFS_OPTS)
  message(STATUS "pvtDefs: ${pvtDefs}")
  message(STATUS "pvtOpts: ${pvtOpts}")
  message(STATUS "linkOpts: ${linkOpts}")
endif()
