#ifndef CCX_PQC_SPIKE_H
#define CCX_PQC_SPIKE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct { size_t pk, sk, ct_or_sig, ss; int32_t ok; } PqSizes;
PqSizes ccx_mlkem768_selftest(void);
PqSizes ccx_mldsa65_selftest(void);
#ifdef __cplusplus
}
#endif
#endif
