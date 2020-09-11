package com.horizen.examples.car.box.data;

import com.horizen.box.data.NoncedBoxData;
import com.horizen.box.data.RegularBoxData;
import com.horizen.proposition.PublicKey25519Proposition;
import com.horizen.transaction.OutputDataSource;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BuyCarOutputDataSource implements OutputDataSource
{
  private final CarSellOrderBoxData carSellOrderBoxData;
  private final boolean isSeller;

  public BuyCarOutputDataSource(CarSellOrderBoxData carSellOrderBoxData, boolean isSeller)
  {
    this.carSellOrderBoxData = carSellOrderBoxData;
    this.isSeller = isSeller;
  }

  @Override
  public List<? extends NoncedBoxData> getBoxData()
  {
    PublicKey25519Proposition ownerProposition = PublicKey25519Proposition.parseBytes(carSellOrderBoxData.proposition().getOwnerPublicKeyBytes());

    if (isSeller) {
      CarBoxData carBoxData = new CarBoxData(ownerProposition, carSellOrderBoxData.getVin(), carSellOrderBoxData.getYear(), carSellOrderBoxData.getModel(), carSellOrderBoxData.getColor());
      return Collections.singletonList(carBoxData);
    }
    else {
      PublicKey25519Proposition newOwnerProposition = PublicKey25519Proposition.parseBytes(carSellOrderBoxData.proposition().getBuyerPublicKeyBytes());
      CarBoxData carBoxData = new CarBoxData(newOwnerProposition, carSellOrderBoxData.getVin(), carSellOrderBoxData.getYear(), carSellOrderBoxData.getModel(), carSellOrderBoxData.getColor());

      RegularBoxData carPayment = new RegularBoxData(ownerProposition, carSellOrderBoxData.value()); //where value() is actually car price

      List<NoncedBoxData> boxesData = new ArrayList<>();
      boxesData.add(carBoxData);
      boxesData.add(carPayment);
      return boxesData;
    }
  }
}
