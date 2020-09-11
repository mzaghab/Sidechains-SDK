package com.horizen.examples.car.transaction;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.horizen.box.BoxUnlocker;
import com.horizen.box.NoncedBox;
import com.horizen.box.data.RegularBoxData;
import com.horizen.companion.SidechainBoxesDataCompanion;
import com.horizen.companion.SidechainProofsCompanion;
import com.horizen.examples.car.box.CarSellOrderBox;
import com.horizen.examples.car.info.CarSellOrderInfo;
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

import static com.horizen.examples.car.transaction.CarRegistryTransactionsIdsEnum.SellCarTransactionId;

// SellCarTransaction is nested from AbstractRegularTransaction so support regular coins transmission as well.
// SellCarTransaction was designed to create a SellOrder for a specific buyer for given CarBox owned by the user.
// As outputs it contains possible RegularBoxes(to pay fee and make change) and new CarSellOrder entry.
// As unlockers it contains RegularBoxes and CarBox to open.
public final class SellCarTransaction2 extends AbstractRegularTransaction2 {

  public SellCarTransaction2(List<byte[]> inputBoxIds,
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
    return SellCarTransactionId.id();
  }

  // Define object serialization, that should serialize both parent class entries and CarSellOrderInfo as well
  @Override
  public byte[] bytes() {
    ByteArrayOutputStream inputsIdsStream = new ByteArrayOutputStream();
    for(byte[] id: inputRegularBoxIds)
      inputsIdsStream.write(id, 0, id.length);

    byte[] inputRegularBoxIdsBytes = inputsIdsStream.toByteArray();

    byte[] inputRegularBoxProofsBytes = regularBoxProofsSerializer.toBytes(inputRegularBoxProofs);

    byte[] outputRegularBoxesDataBytes = regularBoxDataListSerializer.toBytes(outputRegularBoxesData);

    byte[] carSellOrderInfoBytes = carSellOrderInfo.bytes();

    return Bytes.concat(
        Longs.toByteArray(fee()),                               // 8 bytes
        Longs.toByteArray(timestamp()),                         // 8 bytes
        Ints.toByteArray(inputRegularBoxIdsBytes.length),       // 4 bytes
        inputRegularBoxIdsBytes,                                // depends on previous value (>=4 bytes)
        Ints.toByteArray(inputRegularBoxProofsBytes.length),    // 4 bytes
        inputRegularBoxProofsBytes,                             // depends on previous value (>=4 bytes)
        Ints.toByteArray(outputRegularBoxesDataBytes.length),   // 4 bytes
        outputRegularBoxesDataBytes,                            // depends on previous value (>=4 bytes)
        Ints.toByteArray(carSellOrderInfoBytes.length),         // 4 bytes
        carSellOrderInfoBytes                                   // depends on previous value (>=4 bytes)
    );
  }

  // Define object deserialization similar to 'toBytes()' representation.
  public static SellCarTransaction parseBytes(byte[] bytes) {
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

    CarSellOrderInfo carSellOrderInfo = CarSellOrderInfo.parseBytes(Arrays.copyOfRange(bytes, offset, offset + batchSize));

    return new SellCarTransaction(inputRegularBoxIds, inputRegularBoxProofs, outputRegularBoxesData, carSellOrderInfo, fee, timestamp);
  }

  // Set specific Serializer for SellCarTransaction class.
  @Override
  public TransactionSerializer serializer() {
    return SellCarTransactionSerializer.getSerializer();
  }
}