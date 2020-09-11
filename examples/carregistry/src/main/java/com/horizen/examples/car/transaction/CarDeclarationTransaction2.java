package com.horizen.examples.car.transaction;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.horizen.box.NoncedBox;
import com.horizen.box.data.RegularBoxData;
import com.horizen.companion.SidechainBoxesDataCompanion;
import com.horizen.companion.SidechainProofsCompanion;
import com.horizen.examples.car.box.CarBox;
import com.horizen.examples.car.box.data.CarBoxData;
import com.horizen.examples.car.box.data.CarBoxDataSerializer;
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

import static com.horizen.examples.car.transaction.CarRegistryTransactionsIdsEnum.CarDeclarationTransactionId;

// CarDeclarationTransaction is nested from AbstractRegularTransaction so support regular coins transmission as well.
// Moreover it was designed to declare new Cars in the sidechain network.
// As outputs it contains possible RegularBoxes(to pay fee and change) and new CarBox entry.
// No specific unlockers to parent class logic, but has specific new box.
// TODO: add specific mempool incompatibility checker to deprecate keeping in the Mempool txs that declare the same Car.
public final class CarDeclarationTransaction2 extends AbstractRegularTransaction2 {

  public CarDeclarationTransaction2(List<byte[]> inputRegularBoxIds,
                                    List<OutputDataSource> outputRegularBoxesData,
                                    List<Proof> inputBoxProofs,
                                    Long fee,
                                    Long timestamp,
                                    Object dummyData) {
    super(inputRegularBoxIds, outputRegularBoxesData, inputBoxProofs, fee, timestamp, dummyData);
  }

  // Specify the unique custom transaction id.
  @Override
  public byte transactionTypeId() {
    return CarDeclarationTransactionId.id();
  }

  // Define object serialization, that should serialize both parent class entries and CarBoxData as well
  @Override
  public byte[] bytes() {
    ByteArrayOutputStream inputsIdsStream = new ByteArrayOutputStream();
    for(byte[] id: inputBoxIds)
      inputsIdsStream.write(id, 0, id.length);

    byte[] inputRegularBoxIdsBytes = inputsIdsStream.toByteArray();

    byte[] inputRegularBoxProofsBytes = regularBoxProofsSerializer.toBytes(inputRegularBoxProofs);

    byte[] outputRegularBoxesDataBytes = regularBoxDataListSerializer.toBytes(outputRegularBoxesData);

    byte[] outputCarBoxDataBytes = outputCarBoxData.bytes();

    return Bytes.concat(
        Longs.toByteArray(fee()),                               // 8 bytes
        Longs.toByteArray(timestamp()),                         // 8 bytes
        Ints.toByteArray(inputRegularBoxIdsBytes.length),       // 4 bytes
        inputRegularBoxIdsBytes,                                // depends on previous value (>=4 bytes)
        Ints.toByteArray(inputRegularBoxProofsBytes.length),    // 4 bytes
        inputRegularBoxProofsBytes,                             // depends on previous value (>=4 bytes)
        Ints.toByteArray(outputRegularBoxesDataBytes.length),   // 4 bytes
        outputRegularBoxesDataBytes,                            // depends on previous value (>=4 bytes)
        Ints.toByteArray(outputCarBoxDataBytes.length),         // 4 bytes
        outputCarBoxDataBytes                                   // depends on previous value (>=4 bytes)
    );
  }

  // Define object deserialization similar to 'toBytes()' representation.
  public static CarDeclarationTransaction parseBytes(byte[] bytes) {
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

    CarBoxData outputCarBoxData = CarBoxDataSerializer.getSerializer().parseBytes(Arrays.copyOfRange(bytes, offset, offset + batchSize));

    return new CarDeclarationTransaction(inputRegularBoxIds, inputRegularBoxProofs, outputRegularBoxesData, outputCarBoxData, fee, timestamp);
  }

  // Set specific Serializer for CarDeclarationTransaction class.
  @Override
  public TransactionSerializer serializer() {
    return CarDeclarationTransactionSerializer.getSerializer();
  }
}
