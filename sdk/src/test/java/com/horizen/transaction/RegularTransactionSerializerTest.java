package com.horizen.transaction;

import com.horizen.box.NoncedBox;
import com.horizen.box.RegularBox;
import com.horizen.box.data.BoxData;
import com.horizen.box.data.ForgerBoxData;
import com.horizen.box.data.RegularBoxData;
import com.horizen.box.data.WithdrawalRequestBoxData;
import com.horizen.fixtures.BoxFixtureClass;
import com.horizen.proposition.MCPublicKeyHashProposition;
import com.horizen.proposition.Proposition;
import com.horizen.secret.PrivateKey25519;
import com.horizen.secret.PrivateKey25519Creator;
import com.horizen.utils.BytesUtils;
import com.horizen.utils.Pair;
import org.junit.Before;
import org.junit.Test;
import scala.util.Try;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class RegularTransactionSerializerTest extends BoxFixtureClass {
    RegularTransaction transaction;

    @Before
    public void beforeEachTest() {
        long fee = 10;
        long timestamp = 1547798549470L;

        PrivateKey25519Creator creator = PrivateKey25519Creator.getInstance();
        PrivateKey25519 pk1 = creator.generateSecret("test_seed1".getBytes());
        PrivateKey25519 pk2 = creator.generateSecret("test_seed2".getBytes());
        PrivateKey25519 pk3 = creator.generateSecret("test_seed3".getBytes());

        ArrayList<Pair<RegularBox, PrivateKey25519>> from = new ArrayList<>();
        from.add(new Pair<>(getRegularBox(pk1.publicImage(), 1, 60), pk1));
        from.add(new Pair<>(getRegularBox(pk2.publicImage(), 2, 50), pk2));
        from.add(new Pair<>(getRegularBox(pk3.publicImage(), 3, 90), pk3));

        PrivateKey25519 pk4 = creator.generateSecret("test_seed4".getBytes());
        PrivateKey25519 pk5 = creator.generateSecret("test_seed5".getBytes());
        PrivateKey25519 pk6 = creator.generateSecret("test_seed6".getBytes());
        PrivateKey25519 pk7 = creator.generateSecret("test_seed7".getBytes());

        List<BoxData<? extends Proposition, ? extends NoncedBox<? extends Proposition>>> to = new ArrayList<>();
        to.add(new RegularBoxData(pk4.publicImage(), 10L));
        to.add(new RegularBoxData(pk5.publicImage(), 20L));
        to.add(new RegularBoxData(pk6.publicImage(), 30L));

        to.add(new WithdrawalRequestBoxData(new MCPublicKeyHashProposition(BytesUtils.fromHexString("811d42a49dffaee0cb600dee740604b4d5bd0cfb")), 40L));
        to.add(new WithdrawalRequestBoxData(new MCPublicKeyHashProposition(BytesUtils.fromHexString("088f87e1600d5b08eccc240ddd9bd59717d617f1")), 20L));

        to.add(new ForgerBoxData(pk7.publicImage(), 20L, pk7.publicImage(), getVRFPublicKey(111)));
        to.add(new ForgerBoxData(pk7.publicImage(), 50L, pk6.publicImage(), getVRFPublicKey(221)));

        // Note: current transaction bytes are also stored in "src/test/resources/regulartransaction_hex"
        transaction = RegularTransaction.create(from, to, fee, timestamp);

//      Uncomment and run if you want to update regression data.
        /*
        try {
            BufferedWriter out = new BufferedWriter(new FileWriter("src/test/resources/regulartransaction_hex"));
            out.write(BytesUtils.toHexString(transaction.bytes()));
            out.close();
        } catch (Throwable e) {
        }
        */
    }

    @Test
    public void serializationTest() {
        TransactionSerializer serializer = transaction.serializer();
        byte[] bytes = serializer.toBytes(transaction);

        // Test 1: Correct bytes deserialization
        Try<RegularTransaction> t = serializer.parseBytesTry(bytes);
        assertTrue("Transaction serialization failed.", t.isSuccess());
        assertEquals("Deserialized transactions expected to be equal", transaction.id(), t.get().id());


        // Test 2: try to parse broken bytes
        boolean failureExpected = serializer.parseBytesTry("broken bytes".getBytes()).isFailure();
        assertTrue("Failure during parsing expected", failureExpected);
    }

    @Test
    public void regressionTest() {
        byte[] bytes;
        try {
            ClassLoader classLoader = getClass().getClassLoader();
            FileReader file = new FileReader(classLoader.getResource("regulartransaction_hex").getFile());
            bytes = BytesUtils.fromHexString(new BufferedReader(file).readLine());
        }
        catch (Exception e) {
            fail(e.toString());
            return;
        }

        TransactionSerializer serializer = transaction.serializer();
        Try<RegularTransaction> t = serializer.parseBytesTry(bytes);
        assertTrue("Transaction serialization failed.", t.isSuccess());

        RegularTransaction parsedTransaction = t.get();
        assertEquals("Transaction is different to origin.", transaction.id(), parsedTransaction.id());
        assertEquals("Transaction is different to origin.", transaction.fee(), parsedTransaction.fee());
        assertEquals("Transaction is different to origin.", transaction.timestamp(), parsedTransaction.timestamp());
    }
}