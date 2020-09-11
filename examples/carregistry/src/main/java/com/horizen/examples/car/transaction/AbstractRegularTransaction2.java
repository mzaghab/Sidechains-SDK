package com.horizen.examples.car.transaction;

import com.horizen.box.BoxUnlocker;
import com.horizen.box.NoncedBox;
import com.horizen.box.data.NoncedBoxData;
import com.horizen.proof.Proof;
import com.horizen.proposition.Proposition;
import com.horizen.transaction.OutputDataSource;
import com.horizen.transaction.SidechainTransaction;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

// AbstractRegularTransaction is an abstract class that was designed to work with RegularBoxes only.
// This class can spent RegularBoxes and create new RegularBoxes.
// It also support fee payment logic.
public abstract class AbstractRegularTransaction2 extends SidechainTransaction<Proposition, NoncedBox<Proposition>> {

  protected List<byte[]> inputBoxIds;
  protected List<Proof> inputBoxesProofs;
  protected List<OutputDataSource> outputDataSources;

  protected long fee;
  protected long timestamp;

  private List<NoncedBox<Proposition>> newBoxes;

  public AbstractRegularTransaction2(List<byte[]> inputBoxIds,              // regular box ids to spent
                                     List<OutputDataSource> outputBoxesData,  // destinations where to send regular coins
                                     List<Proof> inputBoxProofs,   // proofs to spent regular boxes
                                     long fee,                                     // fee to be paid
                                     long timestamp,
                                     Object dummyData) {                             // creation time in milliseconds from epoch
    // Number of input ids should be equal to number of proofs, otherwise transaction is for sure invalid.
    if(inputBoxIds.size() != inputBoxProofs.size())
      throw new IllegalArgumentException("Regular box inputs list size is different to proving signatures list size!");

    this.inputBoxIds = inputBoxIds;
    this.inputBoxesProofs = inputBoxProofs;
    this.outputDataSources = outputBoxesData;
    this.fee = fee;
    this.timestamp = timestamp;
  }


  // Box ids to open and proofs is expected to be aggregated together and represented as Unlockers.
  // Important: all boxes which must be opened as a part of the Transaction MUST be represented as Unlocker.
  @Override
  public List<BoxUnlocker<Proposition>> unlockers() {
    // All the transactions expected to be immutable, so we keep this list cached to avoid redundant calculations.
    List<BoxUnlocker<Proposition>> unlockers = new ArrayList<>();
    // Fill the list with the regular inputs.
    for (int i = 0; i < inputBoxIds.size() && i < inputBoxesProofs.size(); i++) {
      int finalI = i;
      BoxUnlocker<Proposition> unlocker = new BoxUnlocker<Proposition>() {
        @Override
        public byte[] closedBoxId() {
          return inputBoxIds.get(finalI);
        }

        @Override
        public Proof boxKey() {
          return inputBoxesProofs.get(finalI);
        }
      };
      unlockers.add(unlocker);
    }

    return unlockers;
  }

  // Specify the output boxes.
  // Nonce calculation algorithm is deterministic. So it's forbidden to set nonce in different way.
  // The check for proper nonce is defined in SidechainTransaction.semanticValidity method.
  // Such an algorithm is needed to disallow box ids manipulation and different vulnerabilities related to this.
  @Override
  public List<NoncedBox<Proposition>> newBoxes() {
    if(newBoxes == null) {
      newBoxes = new ArrayList<>();

      List<NoncedBoxData<Proposition, NoncedBox<Proposition>>> boxesData
          = outputDataSources.stream().flatMap(s -> s.getBoxData().stream()).collect(Collectors.toList());

      for (int i = 0; i < boxesData.size(); i++) {
        NoncedBoxData<Proposition, NoncedBox<Proposition>> boxData = boxesData.get(i);
        long nonce = getNewBoxNonce(boxData.proposition(), i);
        newBoxes.add(boxData.getBox(nonce));
      }
    }
    return Collections.unmodifiableList(newBoxes);
  }

  @Override
  public long fee() {
    return fee;
  }

  @Override
  public long timestamp() {
    return timestamp;
  }

  @Override
  public boolean transactionSemanticValidity() {
    if(fee < 0 || timestamp < 0)
      return false;

    // check that we have enough proofs.
    if(inputBoxIds.size() != inputBoxesProofs.size())
      return false;

    return true;
  }
}
