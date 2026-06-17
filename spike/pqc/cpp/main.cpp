#include "pqc.h"
#include <cstdio>
int main() {
  PqSizes k = ccx_mlkem768_selftest();
  printf("ML-KEM-768  pk=%zu sk=%zu ct=%zu ss=%zu  roundtrip_ok=%d\n", k.pk,k.sk,k.ct_or_sig,k.ss,k.ok);
  PqSizes d = ccx_mldsa65_selftest();
  printf("ML-DSA(Dil3) pk=%zu sk=%zu sig=%zu  verify_ok=%d\n", d.pk,d.sk,d.ct_or_sig,d.ok);
  return (k.ok && d.ok) ? 0 : 1;
}
