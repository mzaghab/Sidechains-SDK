package com.horizen.examples.car.api;

import akka.http.javadsl.server.Route;
import com.fasterxml.jackson.annotation.JsonView;
import com.horizen.api.http.ApiResponse;
import com.horizen.api.http.ApplicationApiGroup;
import com.horizen.api.http.ErrorResponse;
import com.horizen.api.http.SuccessResponse;
import com.horizen.box.RegularBox;
import com.horizen.box.data.RegularBoxData;
import com.horizen.companion.SidechainBoxesDataCompanion;
import com.horizen.companion.SidechainProofsCompanion;
import com.horizen.companion.SidechainTransactionsCompanion;
import com.horizen.examples.car.api.request.SpendCarSellOrderRequest;
import com.horizen.examples.car.api.request.CreateCarBoxRequest;
import com.horizen.examples.car.api.request.CreateCarSellOrderRequest;
import com.horizen.examples.car.box.CarBox;
import com.horizen.examples.car.box.CarSellOrderBox;
import com.horizen.examples.car.box.data.CarBoxData;
import com.horizen.examples.car.info.CarBuyOrderInfo;
import com.horizen.examples.car.info.CarSellOrderInfo;
import com.horizen.examples.car.proof.SellOrderSpendingProof;
import com.horizen.examples.car.transaction.BuyCarTransaction;
import com.horizen.examples.car.transaction.CarDeclarationTransaction;
import com.horizen.examples.car.transaction.SellCarTransaction;
import com.horizen.node.NodeMemoryPool;
import com.horizen.node.SidechainNodeView;
import com.horizen.proof.Signature25519;
import com.horizen.proposition.Proposition;
import com.horizen.proposition.PublicKey25519Proposition;
import com.horizen.proposition.PublicKey25519PropositionSerializer;
import com.horizen.secret.Secret;
import com.horizen.serialization.Views;
import com.horizen.transaction.BoxTransaction;
import com.horizen.utils.ByteArrayWrapper;
import com.horizen.utils.BytesUtils;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import scala.Option;
import scala.Some;

import com.horizen.box.Box;

import java.util.*;

import static com.horizen.proof.Signature25519.SIGNATURE_LENGTH;

//simple way to add description for usage in swagger?
public class CarApi extends ApplicationApiGroup {

    private final SidechainTransactionsCompanion sidechainTransactionsCompanion;
    private final SidechainBoxesDataCompanion sidechainBoxesDataCompanion;
    private final SidechainProofsCompanion sidechainProofsCompanion;

    public CarApi(SidechainTransactionsCompanion sidechainTransactionsCompanion,
                  SidechainBoxesDataCompanion sidechainBoxesDataCompanion,
                  SidechainProofsCompanion sidechainProofsCompanion) {
        this.sidechainTransactionsCompanion = sidechainTransactionsCompanion;
        this.sidechainBoxesDataCompanion = sidechainBoxesDataCompanion;
        this.sidechainProofsCompanion = sidechainProofsCompanion;
    }

    @Override
    public String basePath() {
        return "carApi";
    }

    @Override
    public List<Route> getRoutes() {
        List<Route> routes = new ArrayList<>();
        routes.add(bindPostRequest("createCar", this::createCar, CreateCarBoxRequest.class));
        routes.add(bindPostRequest("createCarSellOrder", this::createCarSellOrder, CreateCarSellOrderRequest.class));
        routes.add(bindPostRequest("acceptCarSellOrder", this::acceptCarSellOrder, SpendCarSellOrderRequest.class));
        routes.add(bindPostRequest("cancelCarSellOrder", this::cancelCarSellOrder, SpendCarSellOrderRequest.class));
        return routes;
    }

    /*
      Route to create car (register new car in the Sidechain).
      Input parameters are car properties and fee amount to pay.
      Route checks if the is enough regular box balance to pay fee and then creates CarDeclarationTransaction.
      Output of this transaction is new Car Box token.
      Returns the hex representation of the transaction.
    */
    private ApiResponse createCar(SidechainNodeView view, CreateCarBoxRequest ent) {
        try {
            PublicKey25519Proposition carOwnershipProposition = PublicKey25519PropositionSerializer.getSerializer()
                    .parseBytes(BytesUtils.fromHexString(ent.proposition));

            CarBoxData carBoxData = new CarBoxData(carOwnershipProposition, ent.vin, ent.year, ent.model, ent.color);

            List<Box<Proposition>> paymentBoxes = new ArrayList<>();
            long amountToPay = ent.fee;

            List<byte[]> boxIdsToExclude = boxesFromMempool(view.getNodeMemoryPool());
            List<Box<Proposition>> regularBoxes = view.getNodeWallet().boxesOfType(RegularBox.class, boxIdsToExclude);
            int index = 0;
            while (amountToPay > 0 && index < regularBoxes.size()) {
                paymentBoxes.add(regularBoxes.get(index));
                amountToPay -= regularBoxes.get(index).value();
                index++;
            }

            if (amountToPay > 0) {
                throw new IllegalStateException("Not enough coins to pay the fee.");
            }

            long change = Math.abs(amountToPay);
            List<RegularBoxData> regularOutputs = new ArrayList<>();
            if (change > 0)
                regularOutputs.add(new RegularBoxData((PublicKey25519Proposition) paymentBoxes.get(0).proposition(), change));

            List<byte[]> inputIds = new ArrayList<>();
            for (Box b : paymentBoxes)
                inputIds.add(b.id());

            List fakeProofs = Collections.nCopies(inputIds.size(), null);
            Long timestamp = System.currentTimeMillis();

            CarDeclarationTransaction unsignedTransaction = new CarDeclarationTransaction(
                    inputIds,
                    fakeProofs,
                    regularOutputs,
                    carBoxData,
                    ent.fee,
                    timestamp);

            byte[] messageToSign = unsignedTransaction.messageToSign();
            List<Signature25519> proofs = new ArrayList<>();
            for (Box<Proposition> box : paymentBoxes) {
                proofs.add((Signature25519) view.getNodeWallet().secretByPublicKey(box.proposition()).get().sign(messageToSign));
            }

            CarDeclarationTransaction signedTransaction = new CarDeclarationTransaction(
                    inputIds,
                    proofs,
                    regularOutputs,
                    carBoxData,
                    ent.fee,
                    timestamp);

            return new TxResponse(ByteUtils.toHexString(sidechainTransactionsCompanion.toBytes((BoxTransaction) signedTransaction)));
        }
        catch (Exception e) {
            return new CarResponseError("0102", "Error during Car declaration.", Some.apply(e));
        }
    }

    /*
      Route to create car sell order.
      Input parameters are Car Box id, sell price and fee amount to pay.
      Route checks if car box exists and then creates SellCarTransaction.
      Output of this transaction is new Car Sell Order token.
      Returns the hex representation of the transaction.
    */
    private ApiResponse createCarSellOrder(SidechainNodeView view, CreateCarSellOrderRequest ent) {
        try {
            CarBox carBox = null;

            for (Box b : view.getNodeWallet().boxesOfType(CarBox.class)) {
                if (Arrays.equals(b.id(), BytesUtils.fromHexString(ent.carBoxId)))
                    carBox = (CarBox) b;
            }

            if (carBox == null)
                throw new IllegalArgumentException("CarBox with given box id not found in the Wallet.");

            PublicKey25519Proposition carBuyerProposition = PublicKey25519PropositionSerializer.getSerializer()
                    .parseBytes(BytesUtils.fromHexString(ent.buyerProposition));

            // Get Regular boxes to pay fee
            List<Box<Proposition>> paymentBoxes = new ArrayList<>();
            long amountToPay = ent.fee;

            List<byte[]> boxIdsToExclude = boxesFromMempool(view.getNodeMemoryPool());
            List<Box<Proposition>> regularBoxes = view.getNodeWallet().boxesOfType(RegularBox.class, boxIdsToExclude);
            int index = 0;
            while (amountToPay > 0 && index < regularBoxes.size()) {
                paymentBoxes.add(regularBoxes.get(index));
                amountToPay -= regularBoxes.get(index).value();
                index++;
            }

            if (amountToPay > 0) {
                throw new IllegalStateException("Not enough coins to pay the fee.");
            }

            long change = Math.abs(amountToPay);
            List<RegularBoxData> regularOutputs = new ArrayList<>();
            if (change > 0)
                regularOutputs.add(new RegularBoxData((PublicKey25519Proposition) paymentBoxes.get(0).proposition(), change));

            List<byte[]> inputRegularBoxIds = new ArrayList<>();
            for (Box b : paymentBoxes)
                inputRegularBoxIds.add(b.id());

            CarSellOrderInfo fakeSaleOrderInfo = new CarSellOrderInfo(carBox, null, ent.sellPrice, carBuyerProposition);


            List<Signature25519> fakeRegularInputProofs = Collections.nCopies(inputRegularBoxIds.size(), null);
            Long timestamp = System.currentTimeMillis();

            SellCarTransaction unsignedTransaction = new SellCarTransaction(
                    inputRegularBoxIds,
                    fakeRegularInputProofs,
                    regularOutputs,
                    fakeSaleOrderInfo,
                    ent.fee,
                    timestamp);

            byte[] messageToSign = unsignedTransaction.messageToSign();
            List<Signature25519> regularInputProofs = new ArrayList<>();

            for (Box<Proposition> box : paymentBoxes) {
                regularInputProofs.add((Signature25519) view.getNodeWallet().secretByPublicKey(box.proposition()).get().sign(messageToSign));
            }

            CarSellOrderInfo saleOrderInfo = new CarSellOrderInfo(
                    carBox,
                    (Signature25519)view.getNodeWallet().secretByPublicKey(carBox.proposition()).get().sign(messageToSign),
                    ent.sellPrice,
                    carBuyerProposition);


            SellCarTransaction transaction = new SellCarTransaction(
                    inputRegularBoxIds,
                    regularInputProofs,
                    regularOutputs,
                    saleOrderInfo,
                    ent.fee,
                    timestamp);

            return new TxResponse(ByteUtils.toHexString(sidechainTransactionsCompanion.toBytes((BoxTransaction) transaction)));
        }
        catch (Exception e) {
            return new CarResponseError("0102", "Error during Car Sell Order sell operation.", Some.apply(e));
        }
    }

    /*
      Route to accept car sell order by the specified buyer.
      Input parameter is Car Sell Order box id.
      Route checks if car sell order box exist, buyer proposition is controlled by Nodes wallet and
      wallet has enough balance to pay the car price and fee. And then creates BuyCarTransaction.
      Output of this transaction is new Car Box (with buyer as owner) and regular box with coins amount
      equivalent to sell price as payment for car to previous car owner.
      Returns the hex representation of the transaction.
    */
    private ApiResponse acceptCarSellOrder(SidechainNodeView view, SpendCarSellOrderRequest ent) {
        try {
            CarSellOrderBox carSellOrderBox = (CarSellOrderBox)view.getNodeState().getClosedBox(BytesUtils.fromHexString(ent.carSellOrderId)).get();

            Optional<Secret> buyerSecretOption = view.getNodeWallet().secretByPublicKey(
                    new PublicKey25519Proposition(carSellOrderBox.proposition().getBuyerPublicKeyBytes()));
            if(!buyerSecretOption.isPresent()) {
                return new CarResponseError("0100", "Can't buy the car, because the buyer proposition is not owned by the Node.", Option.empty());
            }

            // Get Regular boxes to pay the car price + fee
            List<Box<Proposition>> paymentBoxes = new ArrayList<>();
            long amountToPay = carSellOrderBox.getPrice() + ent.fee;

            List<byte[]> boxIdsToExclude = boxesFromMempool(view.getNodeMemoryPool());
            List<Box<Proposition>> regularBoxes = view.getNodeWallet().boxesOfType(RegularBox.class, boxIdsToExclude);
            int index = 0;
            while (amountToPay > 0 && index < regularBoxes.size()) {
                paymentBoxes.add(regularBoxes.get(index));
                amountToPay -= regularBoxes.get(index).value();
                index++;
            }

            if (amountToPay > 0) {
                throw new IllegalStateException("Not enough coins to pay the fee.");
            }

            long change = Math.abs(amountToPay);
            List<RegularBoxData> regularOutputs = new ArrayList<>();
            if (change > 0)
                regularOutputs.add(new RegularBoxData((PublicKey25519Proposition) paymentBoxes.get(0).proposition(), change));

            List<byte[]> inputRegularBoxIds = new ArrayList<>();
            for (Box b : paymentBoxes)
                inputRegularBoxIds.add(b.id());

            boolean isSeller = false;
            SellOrderSpendingProof fakeSellProof = new SellOrderSpendingProof(new byte[SellOrderSpendingProof.SIGNATURE_LENGTH], isSeller);
            CarBuyOrderInfo fakeBuyOrderInfo = new CarBuyOrderInfo(carSellOrderBox, fakeSellProof);

            List<Signature25519> fakeRegularInputProofs = Collections.nCopies(inputRegularBoxIds.size(), null);
            Long timestamp = System.currentTimeMillis();

            BuyCarTransaction unsignedTransaction = new BuyCarTransaction(
                    inputRegularBoxIds,
                    fakeRegularInputProofs,
                    regularOutputs,
                    fakeBuyOrderInfo,
                    ent.fee,
                    timestamp);

            byte[] messageToSign = unsignedTransaction.messageToSign();
            List<Signature25519> regularInputProofs = new ArrayList<>();

            for (Box<Proposition> box : paymentBoxes) {
                regularInputProofs.add((Signature25519) view.getNodeWallet().secretByPublicKey(box.proposition()).get().sign(messageToSign));
            }

            SellOrderSpendingProof buyerProof = new SellOrderSpendingProof(
                    buyerSecretOption.get().sign(messageToSign).bytes(),
                    isSeller
            );

            CarBuyOrderInfo buyOrderInfo = new CarBuyOrderInfo(carSellOrderBox, buyerProof);

            BuyCarTransaction transaction = new BuyCarTransaction(
                    inputRegularBoxIds,
                    regularInputProofs,
                    regularOutputs,
                    buyOrderInfo,
                    ent.fee,
                    timestamp);

            return new TxResponse(ByteUtils.toHexString(sidechainTransactionsCompanion.toBytes((BoxTransaction) transaction)));
        } catch (Exception e) {
            return new CarResponseError("0103", "Error during Car Sell Order buy operation.", Some.apply(e));
        }
    }

    /*
      Route to cancel car sell order. Car Sell order can be cancelled by the owner only.
      Input parameters are Car Sell Order box id and fee to pay.
      Route checks if car sell order exists and owned by the node Wallet and then creates BuyCarTransaction.
      Output of this transaction is new Car Box (with seller as owner).
      Returns the hex representation of the transaction.
    */
    private ApiResponse cancelCarSellOrder(SidechainNodeView view, SpendCarSellOrderRequest ent) {
        try {
            Optional<Box > carSellOrderBoxOption = view.getNodeState().getClosedBox(BytesUtils.fromHexString(ent.carSellOrderId));

            if (!carSellOrderBoxOption.isPresent())
                throw new IllegalArgumentException("CarSellOrderBox with given box id not found in the State.");

            CarSellOrderBox carSellOrderBox = (CarSellOrderBox)carSellOrderBoxOption.get();

            // Get Regular boxes to pay the fee
            List<Box<Proposition>> paymentBoxes = new ArrayList<>();
            long amountToPay = ent.fee;

            List<byte[]> boxIdsToExclude = boxesFromMempool(view.getNodeMemoryPool());
            List<Box<Proposition>> regularBoxes = view.getNodeWallet().boxesOfType(RegularBox.class, boxIdsToExclude);
            int index = 0;
            while (amountToPay > 0 && index < regularBoxes.size()) {
                paymentBoxes.add(regularBoxes.get(index));
                amountToPay -= regularBoxes.get(index).value();
                index++;
            }

            if (amountToPay > 0) {
                throw new IllegalStateException("Not enough coins to pay the fee.");
            }

            long change = Math.abs(amountToPay);
            List<RegularBoxData> regularOutputs = new ArrayList<>();
            if (change > 0)
                regularOutputs.add(new RegularBoxData((PublicKey25519Proposition) paymentBoxes.get(0).proposition(), change));

            List<byte[]> inputRegularBoxIds = new ArrayList<>();
            for (Box b : paymentBoxes)
                inputRegularBoxIds.add(b.id());

            boolean isSeller = true;
            SellOrderSpendingProof fakeOwnerProof = new SellOrderSpendingProof(new byte[SellOrderSpendingProof.SIGNATURE_LENGTH], isSeller);
            CarBuyOrderInfo fakeBuyOrderInfo = new CarBuyOrderInfo(carSellOrderBox, fakeOwnerProof);

            List<Signature25519> fakeRegularInputProofs = Collections.nCopies(inputRegularBoxIds.size(), null);
            Long timestamp = System.currentTimeMillis();

            BuyCarTransaction unsignedTransaction = new BuyCarTransaction(
                    inputRegularBoxIds,
                    fakeRegularInputProofs,
                    regularOutputs,
                    fakeBuyOrderInfo,
                    ent.fee,
                    timestamp);

            byte[] messageToSign = unsignedTransaction.messageToSign();
            List<Signature25519> regularInputProofs = new ArrayList<>();

            for (Box<Proposition> box : paymentBoxes) {
                regularInputProofs.add((Signature25519) view.getNodeWallet().secretByPublicKey(box.proposition()).get().sign(messageToSign));
            }

            Secret ownerSecret = view.getNodeWallet().secretByPublicKey(
                    new PublicKey25519Proposition(carSellOrderBox.proposition().getOwnerPublicKeyBytes())).get();

            SellOrderSpendingProof ownerProof = new SellOrderSpendingProof(
                    ownerSecret.sign(messageToSign).bytes(),
                    isSeller
            );

            CarBuyOrderInfo buyOrderInfo = new CarBuyOrderInfo(carSellOrderBox, ownerProof);

            BuyCarTransaction transaction = new BuyCarTransaction(
                    inputRegularBoxIds,
                    regularInputProofs,
                    regularOutputs,
                    buyOrderInfo,
                    ent.fee,
                    timestamp);

            return new TxResponse(ByteUtils.toHexString(sidechainTransactionsCompanion.toBytes((BoxTransaction) transaction)));
        } catch (Exception e) {
            return new CarResponseError("0103", "Error during Car Sell Order cancel operation.", Some.apply(e));
        }
    }

    @JsonView(Views.Default.class)
    class TxResponse implements SuccessResponse {
        public String transactionBytes;

        public TxResponse(String transactionBytes) {
            this.transactionBytes = transactionBytes;
        }
    }

    static class CarResponseError implements ErrorResponse {
        private final String code;
        private final String description;
        private final Option<Throwable> exception;

        CarResponseError(String code, String description, Option<Throwable> exception) {
            this.code = code;
            this.description = description;
            this.exception = exception;
        }

        @Override
        public String code() {
            return code;
        }

        @Override
        public String description() {
            return description;
        }

        @Override
        public Option<Throwable> exception() {
            return exception;
        }
    }

    private List<byte[]> boxesFromMempool(NodeMemoryPool mempool) {
        List<byte[]> boxesFromMempool = new ArrayList<>();
        for(BoxTransaction tx : mempool.getTransactions()) {
            Set<ByteArrayWrapper> ids = tx.boxIdsToOpen();
            for(ByteArrayWrapper id : ids) {
                boxesFromMempool.add(id.data());
            }
        }
        return boxesFromMempool;
    }
}

