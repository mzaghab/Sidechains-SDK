package com.horizen.examples.car.transaction;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.horizen.box.BoxUnlocker;
import com.horizen.box.NoncedBox;
import com.horizen.box.RegularBox;
import com.horizen.box.data.RegularBoxData;
import com.horizen.companion.SidechainBoxesDataCompanion;
import com.horizen.companion.SidechainProofsCompanion;
import com.horizen.examples.car.box.CarBox;
import com.horizen.examples.car.info.CarBuyOrderInfo;
import com.horizen.proof.Proof;
import com.horizen.proof.Signature25519;
import com.horizen.proposition.Proposition;
import com.horizen.transaction.OutputDataSource;
import com.horizen.transaction.TransactionSerializer;
import com.horizen.utils.BytesUtils;
import scorex.core.NodeViewModifier$;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.horizen.examples.car.transaction.CarRegistryTransactionsIdsEnum.BuyCarTransactionId;

// BuyCarTransaction is nested from AbstractRegularTransaction so support regular coins transmission as well.
// BuyCarTransaction was designed to accept the SellOrder by specific buyer or to cancel it by the owner.
// As outputs it contains possible RegularBoxes(to pay to the sell order owner and make change) and new CarBox entry.
// As unlockers it contains RegularBoxes and CarSellOrder to open.
public final class BuyCarTransaction2 extends AbstractRegularTransaction2 {

  // CarBuyOrderInfo is a view that describes what sell order to open and who will be the next owner.
  // But inside it contains just a minimum set of info (like CarSellOrderBox itself and proof) that is the unique source of data.
  // So, no one outside controls what will be the specific outputs of this transaction.
  // Any malicious actions will lead to transaction invalidation.
  // For example, if SellOrder was accepted by the buyer specified, CarBuyOrderInfo view returns as the new box data
  // new instance of CarBoxData the owned by the buyer and RegularBoxData with the payment to previous owner.
  private CarBuyOrderInfo carBuyOrderInfo;

  public BuyCarTransaction2(List<byte[]> inputBoxIds,
                            List<OutputDataSource> outputBoxesData,  // destinations where to send regular coins
                            List<Proof> inputBoxProofs,
                            long fee,
                            long timestamp,
                            Object dummyData) {
    super(inputBoxIds, outputBoxesData, inputBoxProofs, fee, timestamp, dummyData);
  }

  // Specify the unique custom transaction id.
  @Override
  public byte transactionTypeId() {
    return BuyCarTransactionId.id();
  }

  // Define object serialization, that should serialize both parent class entries and CarBuyOrderInfo as well
  @Override
  public byte[] bytes() {
    ByteArrayOutputStream inputsIdsStream = new ByteArrayOutputStream();
    for(byte[] id: inputRegularBoxIds)
      inputsIdsStream.write(id, 0, id.length);

    byte[] inputRegularBoxIdsBytes = inputsIdsStream.toByteArray();

    byte[] inputRegularBoxProofsBytes = regularBoxProofsSerializer.toBytes(inputRegularBoxProofs);

    byte[] outputRegularBoxesDataBytes = regularBoxDataListSerializer.toBytes(outputRegularBoxesData);

    byte[] carBuyOrderInfoBytes = carBuyOrderInfo.bytes();

    return Bytes.concat(
        Longs.toByteArray(fee()),                               // 8 bytes
        Longs.toByteArray(timestamp()),                         // 8 bytes
        Ints.toByteArray(inputRegularBoxIdsBytes.length),       // 4 bytes
        inputRegularBoxIdsBytes,                                // depends on previous value (>=4 bytes)
        Ints.toByteArray(inputRegularBoxProofsBytes.length),    // 4 bytes
        inputRegularBoxProofsBytes,                             // depends on previous value (>=4 bytes)
        Ints.toByteArray(outputRegularBoxesDataBytes.length),   // 4 bytes
        outputRegularBoxesDataBytes,                            // depends on previous value (>=4 bytes)
        Ints.toByteArray(carBuyOrderInfoBytes.length),          // 4 bytes
        carBuyOrderInfoBytes                                    // depends on previous value (>=4 bytes)
    );
  }

  // Define object deserialization similar to 'toBytes()' representation.
  public static BuyCarTransaction parseBytes(byte[] bytes) {
    int offset = 0;

    long fee = BytesUtils.getLong(bytes, offset);
    offset += 8;

    long timestamp = BytesUtils.getLong(bytes, offset);
    offset += 8;

    int batchSize = BytesUtils.getInt(bytes, offset);
    offset += 4;

    ArrayList<byte[]> inputRegularBoxIds = new ArrayList<>();
    int idLength = NodeViewModifier$.MODULE$.ModifierIdSize();
    while(batchSize > 0) {
      inputRegularBoxIds.add(Arrays.copyOfRange(bytes, offset, offset + idLength));
      offset += idLength;
      batchSize -= idLength;
    }

    batchSize = BytesUtils.getInt(bytes, offset);
    offset += 4;

    List<Signature25519> inputRegularBoxProofs = regularBoxProofsSerializer.parseBytes(Arrays.copyOfRange(bytes, offset, offset + batchSize));
    offset += batchSize;

    batchSize = BytesUtils.getInt(bytes, offset);
    offset += 4;

    List<RegularBoxData> outputRegularBoxesData = regularBoxDataListSerializer.parseBytes(Arrays.copyOfRange(bytes, offset, offset + batchSize));
    offset += batchSize;

    batchSize = BytesUtils.getInt(bytes, offset);
    offset += 4;

    CarBuyOrderInfo carBuyOrderInfo = CarBuyOrderInfo.parseBytes(Arrays.copyOfRange(bytes, offset, offset + batchSize));

    return new BuyCarTransaction(inputRegularBoxIds, inputRegularBoxProofs, outputRegularBoxesData, carBuyOrderInfo, fee, timestamp);
  }

  // Set specific Serializer for BuyCarTransaction class.
  @Override
  public TransactionSerializer serializer() {
    return BuyCarTransactionSerializer.getSerializer();
  }
}
