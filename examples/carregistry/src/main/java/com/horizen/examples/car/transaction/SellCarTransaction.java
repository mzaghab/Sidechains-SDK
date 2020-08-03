package com.horizen.examples.car.transaction;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.horizen.box.BoxUnlocker;
import com.horizen.box.NoncedBox;
import com.horizen.box.data.RegularBoxData;
import com.horizen.examples.car.box.CarSellOrderBox;
import com.horizen.examples.car.info.CarSellOrderInfo;
import com.horizen.proof.Proof;
import com.horizen.proof.Signature25519;
import com.horizen.proposition.Proposition;
import com.horizen.transaction.TransactionSerializer;
import com.horizen.utils.BytesUtils;
import scorex.core.NodeViewModifier$;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static com.horizen.examples.car.transaction.CarRegistryTransactionsIdsEnum.SellCarTransactionId;
// TODO: add mempool incompatibility checker.
public final class SellCarTransaction extends AbstractRegularTransaction {

    private CarSellOrderInfo carSellOrderInfo;

    private List<NoncedBox<Proposition>> newBoxes;

    public SellCarTransaction(List<byte[]> inputRegularBoxIds,
                              List<Signature25519> inputRegularBoxProofs,
                              List<RegularBoxData> outputRegularBoxesData,
                              CarSellOrderInfo carSellOrderInfo,
                              long fee,
                              long timestamp) {
        super(inputRegularBoxIds, inputRegularBoxProofs, outputRegularBoxesData, fee, timestamp);
        this.carSellOrderInfo = carSellOrderInfo;
    }
    @Override
    public byte transactionTypeId() {
        return SellCarTransactionId.id();
    }

    @Override
    public List<BoxUnlocker<Proposition>> unlockers() {
        List<BoxUnlocker<Proposition>> unlockers = super.unlockers();

        BoxUnlocker<Proposition> unlocker = new BoxUnlocker<Proposition>() {
            @Override
            public byte[] closedBoxId() {
                return carSellOrderInfo.getCarBoxToOpen().id();
            }

            @Override
            public Proof boxKey() {
                return carSellOrderInfo.getCarBoxSpendingProof();
            }
        };
        unlockers.add(unlocker);

        return unlockers;
    }

    @Override
    public List<NoncedBox<Proposition>> newBoxes() {
        if(newBoxes == null) {
            newBoxes = new ArrayList<>(super.newBoxes());
            long nonce = getNewBoxNonce(carSellOrderInfo.getSellOrderBoxData().proposition(), newBoxes.size());
            newBoxes.add((NoncedBox) new CarSellOrderBox(carSellOrderInfo.getSellOrderBoxData(), nonce));

        }
        return Collections.unmodifiableList(newBoxes);
    }

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

    @Override
    public TransactionSerializer serializer() {
        return SellCarTransactionSerializer.getSerializer();
    }
}