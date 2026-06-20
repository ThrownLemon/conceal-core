// v2 transaction lifecycle demo (standalone — no conceal-core consensus code).
// Proves: build -> sign -> serialize(TLV) -> deserialize -> verify -> double-spend reject,
// end-to-end with the ccx-pqc module (real ML-* primitives; stub ring-sig).
#include "pq_ring_sig.h"
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <set>
#include <string>
using B = std::vector<uint8_t>;
static void put_varint(B& o, uint64_t v){ while(v>=0x80){o.push_back((uint8_t)(v|0x80));v>>=7;} o.push_back((uint8_t)v); }
static uint64_t get_varint(const B& b, size_t& p){ uint64_t v=0;int s=0;for(;;){uint8_t c=b[p++];v|=(uint64_t)(c&0x7f)<<s;if(!(c&0x80))break;s+=7;}return v; }
static void put_blob(B& o, const uint8_t* d, size_t n){ put_varint(o,n); o.insert(o.end(), d, d+n); }
static B get_blob(const B& b, size_t& p){ uint64_t n=get_varint(b,p); B r(b.begin()+p, b.begin()+p+n); p+=n; return r; }

int main(){
  const size_t pkb=ccx_pq_pubkey_bytes(), skb=ccx_pq_seckey_bytes(), nfb=ccx_pq_nullifier_bytes();
  const size_t N=16;                        // ring (L1: bigger ring)
  std::vector<B> pks(N,B(pkb)), sks(N,B(skb));
  for(size_t i=0;i<N;i++){ uint8_t seed[32]; memset(seed,(int)(i+1),32);
    ccx_pq_keygen(seed,32,pks[i].data(),pkb,sks[i].data(),skb); }
  size_t signer=5; uint8_t prefix[32]; memset(prefix,0xCD,32);
  B ring(N*pkb); for(size_t i=0;i<N;i++) memcpy(&ring[i*pkb],pks[i].data(),pkb);
  size_t siglen=0; ccx_pq_sign(prefix,32,ring.data(),N,pkb,sks[signer].data(),skb,signer,nullptr,&siglen);
  B sig(siglen); ccx_pq_sign(prefix,32,ring.data(),N,pkb,sks[signer].data(),skb,signer,sig.data(),&siglen);
  B nf(nfb); ccx_pq_nullifier(sks[signer].data(),skb,pks[signer].data(),pkb,nf.data(),nfb);

  // serialize a v2 tx: version, 1 input (ring offsets 0..N-1, nullifier, sig), 1 output (pk, kem stub)
  B tx; put_varint(tx,2); put_varint(tx,0); put_varint(tx,1);
  tx.push_back(0x03); put_varint(tx,1000000); put_varint(tx,N);
  for(size_t i=0;i<N;i++) put_varint(tx, i==0?i:1);   // delta-encoded global indexes
  put_blob(tx, nf.data(), nfb);
  put_varint(tx,1); tx.push_back(0x03); put_varint(tx,990000);
  put_blob(tx, pks[0].data(), pkb); B kem(1088,7); put_blob(tx, kem.data(), kem.size());
  put_blob(tx, sig.data(), sig.size());               // signatures section
  printf("v2 tx serialized: %.1f KB (ring=%zu)\n", tx.size()/1000.0, N);

  // deserialize + validate (resolve ring offsets -> pubkeys from our 'chain'; verify; spent-set)
  static std::set<std::string> spent;
  auto validate = [&](const B& t)->const char*{
    size_t p=0; if(get_varint(t,p)!=2) return "bad-version"; get_varint(t,p);
    uint64_t nin=get_varint(t,p);
    std::vector<B> nfs; std::vector<std::pair<std::vector<uint64_t>,size_t>> ins;
    for(uint64_t i=0;i<nin;i++){ p++; get_varint(t,p); uint64_t rs=get_varint(t,p);
      std::vector<uint64_t> off(rs); for(auto&o:off)o=get_varint(t,p);
      B n=get_blob(t,p); nfs.push_back(n); ins.push_back({off,(size_t)rs}); }
    uint64_t nout=get_varint(t,p);
    for(uint64_t i=0;i<nout;i++){ p++; get_varint(t,p); get_blob(t,p); get_blob(t,p); }
    for(uint64_t i=0;i<nin;i++){ B s=get_blob(t,p);
      // rebuild ring from offsets (delta) -> absolute -> our pubkeys
      B rr(ins[i].second*pkb); uint64_t idx=0;
      for(size_t k=0;k<ins[i].second;k++){ idx = k==0?ins[i].first[k]:idx+ins[i].first[k];
        memcpy(&rr[k*pkb], pks[idx].data(), pkb); }
      if(ccx_pq_verify(prefix,32,rr.data(),ins[i].second,pkb,s.data(),s.size(),nullptr,0)!=0) return "verify-fail";
      std::string key((char*)nfs[i].data(),nfs[i].size());
      if(spent.count(key)) return "DOUBLE-SPEND";
    }
    for(auto&n:nfs) spent.insert(std::string((char*)n.data(),n.size()));
    return "OK";
  };
  printf("validate (first):  %s\n", validate(tx));
  printf("validate (replay): %s   <- double-spend prevention\n", validate(tx));
  return 0;
}
