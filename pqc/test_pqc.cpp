#include "pq_ring_sig.h"
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdint>
int main() {
  ccx_pq_sizes k = ccx_mlkem768_selftest();
  printf("ML-KEM-768  ct=%zu ss=%zu roundtrip_ok=%d\n", k.ct_or_sig, k.ss, k.ok);
  ccx_pq_sizes d = ccx_mldsa_selftest();
  printf("ML-DSA      sig=%zu verify_ok=%d\n", d.ct_or_sig, d.ok);

  size_t pkb=ccx_pq_pubkey_bytes(), skb=ccx_pq_seckey_bytes(), nfb=ccx_pq_nullifier_bytes();
  const size_t N=6;
  std::vector<std::vector<uint8_t>> pks(N,std::vector<uint8_t>(pkb)), sks(N,std::vector<uint8_t>(skb));
  for(size_t i=0;i<N;i++){ uint8_t seed[32]; memset(seed,(int)(i+1),32);
    if(ccx_pq_keygen(seed,32,pks[i].data(),pkb,sks[i].data(),skb)!=0){printf("keygen FAIL\n");return 1;} }
  std::vector<uint8_t> ring(N*pkb);
  for(size_t i=0;i<N;i++) memcpy(&ring[i*pkb],pks[i].data(),pkb);
  size_t signer=2;
  uint8_t msg[32]; memset(msg,0xAB,32);
  size_t siglen=0;
  ccx_pq_sign(msg,32,ring.data(),N,pkb,sks[signer].data(),skb,signer,nullptr,&siglen); // size query
  std::vector<uint8_t> sig(siglen);
  int rs=ccx_pq_sign(msg,32,ring.data(),N,pkb,sks[signer].data(),skb,signer,sig.data(),&siglen);
  std::vector<uint8_t> nf_v(nfb);
  int rv=ccx_pq_verify(msg,32,ring.data(),N,pkb,sig.data(),siglen,nf_v.data(),nfb);
  std::vector<uint8_t> nf_direct(nfb);
  ccx_pq_nullifier(sks[signer].data(),skb,pks[signer].data(),pkb,nf_direct.data(),nfb);
  bool nf_match=memcmp(nf_v.data(),nf_direct.data(),nfb)==0;
  printf("ring-sig(STUB) ring=%zu sig=%zu sign_rc=%d verify_rc=%d nullifier_match=%d\n",N,siglen,rs,rv,(int)nf_match);
  bool all=k.ok&&d.ok&&rs==0&&rv==0&&nf_match;
  printf("ALL=%s\n", all?"PASS":"FAIL");
  return all?0:1;
}
