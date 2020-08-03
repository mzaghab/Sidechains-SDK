package com.horizen.examples.car.api.request;

public class SpendCarSellOrderRequest {
    public String carSellOrderId;
    public long fee;

    public void setCarSellOrderId(String carSellOrderId) {
        this.carSellOrderId = carSellOrderId;
    }

    public void setFee(long fee) {
        this.fee = fee;
    }
}
