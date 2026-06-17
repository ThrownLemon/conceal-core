// CIP-0001 §6.2 / wire-format-v2.md grounding: v2 TLV serialize/deserialize
// round-trip + real serialized size, vs the wire-size-calc formula.
// Faithful CryptoNote encoding: LEB128 varint + length-prefixed blobs.
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
using B=std::vector<uint8_t>;
static void put_varint(B&o,uint64_t v){ while(v>=0x80){o.push_back((uint8_t)(v|0x80));v>>=7;} o.push_back((uint8_t)v); }
static uint64_t get_varint(const B&b,size_t&p){ uint64_t v=0;int s=0;while(true){uint8_t c=b[p++];v|=(uint64_t)(c&0x7f)<<s;if(!(c&0x80))break;s+=7;}return v; }
static void put_blob(B&o,size_t n){ put_varint(o,n); for(size_t i=0;i<n;i++)o.push_back((uint8_t)(i*131+7)); }
static size_t get_blob(const B&b,size_t&p){ uint64_t n=get_varint(b,p); p+=n; return n; }

struct Scheme{ const char*name; size_t ringsig,nullifier,pubkey,kem; };
static void ser_tx(B&o,const Scheme&s,int nin,int nout,int ring){
  put_varint(o,2); put_varint(o,0);                 // version, unlock
  put_varint(o,nin);
  for(int i=0;i<nin;i++){ o.push_back(0x03); put_varint(o,1000000); put_varint(o,ring);
    for(int r=0;r<ring;r++) put_varint(o, r==0?500000:3); put_blob(o,s.nullifier); }
  put_varint(o,nout);
  for(int i=0;i<nout;i++){ o.push_back(0x03); put_varint(o,1000000); put_blob(o,s.pubkey); put_blob(o,s.kem); o.push_back(0x11); }
  put_blob(o,33);                                    // extra
  for(int i=0;i<nin;i++) put_blob(o,s.ringsig);      // signatures (one proof/input)
}
static bool roundtrip(const B&o,const Scheme&s,int nin,int nout){
  size_t p=0; if(get_varint(o,p)!=2)return false; get_varint(o,p);
  uint64_t ci=get_varint(o,p); if((int)ci!=nin)return false;
  for(uint64_t i=0;i<ci;i++){ p++; get_varint(o,p); uint64_t ring=get_varint(o,p); for(uint64_t r=0;r<ring;r++)get_varint(o,p); get_blob(o,p); }
  uint64_t co=get_varint(o,p); if((int)co!=nout)return false;
  for(uint64_t i=0;i<co;i++){ p++; get_varint(o,p); get_blob(o,p); get_blob(o,p); p++; }
  get_blob(o,p); for(uint64_t i=0;i<ci;i++) get_blob(o,p);
  return p==o.size();
}
int main(){
  Scheme schemes[]={ {"MatRiCT-Au",19000,248,4360,1088},{"Falafl",35000,32,4096,1088},{"Raptor",16053,897,897,1088} };
  int prof[][3]={{1,1,6},{2,2,6},{4,7,6},{45,2,6}}; const char*pn[]={"median","avg","p90","fusion"};
  for(auto&s:schemes){ printf("== %s ==\n",s.name);
    for(int k=0;k<4;k++){ B o; ser_tx(o,s,prof[k][0],prof[k][1],prof[k][2]);
      bool rt=roundtrip(o,s,prof[k][0],prof[k][1]);
      printf("  %-7s in=%d out=%d  serialized=%.1f KB  roundtrip=%s\n",pn[k],prof[k][0],prof[k][1],o.size()/1000.0,rt?"OK":"FAIL"); } }
  return 0;
}
