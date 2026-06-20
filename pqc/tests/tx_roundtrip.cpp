// Phase 2 proof: a v3 PQ transaction round-trips through conceal-core's REAL
// serialization (toBinaryArray/fromBinaryArray), with PqKeyInput/PqKeyOutput.
#include "CryptoNote.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/CryptoNoteSerialization.h"
#include <cstdio>
using namespace cn;
int main() {
  Transaction tx; tx.version = 3; tx.unlockTime = 0;
  PqKeyInput in; in.amount = 1000000; in.outputIndexes = {0,1,2,3,4,5};
  in.nullifier = std::vector<uint8_t>(32, 0xAB);
  in.ringSig   = std::vector<uint8_t>(21104, 0xCD);
  tx.inputs.push_back(in);
  TransactionOutput out; out.amount = 990000;
  PqKeyOutput po; po.key = std::vector<uint8_t>(1312, 0x11); po.kemCt = std::vector<uint8_t>(1088, 0x22);
  out.target = po; tx.outputs.push_back(out);

  BinaryArray ba = toBinaryArray(tx);
  printf("serialized v3 PQ tx: %zu bytes\n", ba.size());
  Transaction tx2;
  bool ok = fromBinaryArray(tx2, ba);
  BinaryArray ba2 = toBinaryArray(tx2);
  bool rt = (ba == ba2);
  bool typeok = false; size_t nf = 0, rs = 0;
  if (tx2.inputs.size() == 1 && tx2.inputs[0].type() == typeid(PqKeyInput)) {
    const PqKeyInput& p = boost::get<PqKeyInput>(tx2.inputs[0]);
    nf = p.nullifier.size(); rs = p.ringSig.size(); typeok = true;
  }
  printf("fromBinary=%d roundtrip=%d pqInputType=%d nullifier=%zu ringsig=%zu\n", ok, rt, typeok, nf, rs);
  printf("%s\n", (ok && rt && typeok && nf == 32 && rs == 21104) ? "PASS" : "FAIL");
  return (ok && rt && typeok) ? 0 : 1;
}
