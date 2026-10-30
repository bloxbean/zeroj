package org.zeroj.bindings.cardano;

import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.address.AddressProvider;
import com.bloxbean.cardano.client.api.model.Amount;
import com.bloxbean.cardano.client.api.model.Utxo;
import com.bloxbean.cardano.client.backend.api.DefaultProtocolParamsSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultScriptSupplier;
import com.bloxbean.cardano.client.backend.api.DefaultUtxoSupplier;
import com.bloxbean.cardano.client.backend.blockfrost.service.BFBackendService;
import com.bloxbean.cardano.client.common.model.Networks;
import com.bloxbean.cardano.client.function.helper.SignerProviders;
import com.bloxbean.cardano.client.plutus.spec.BigIntPlutusData;
import com.bloxbean.cardano.client.plutus.spec.BytesPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ConstrPlutusData;
import com.bloxbean.cardano.client.plutus.spec.ListPlutusData;
import com.bloxbean.cardano.client.plutus.spec.PlutusV3Script;
import com.bloxbean.cardano.client.quicktx.QuickTxBuilder;
import com.bloxbean.cardano.client.quicktx.ScriptTx;
import com.bloxbean.cardano.client.quicktx.Tx;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.julclang.clientlib.JulcScriptAdapter;
import org.julclang.clientlib.eval.JulcTransactionEvaluator;
import org.julclang.compiler.JulcCompiler;
import org.julclang.core.PlutusData;
import org.julclang.core.flat.UplcFlatEncoder;
import org.julclang.stdlib.StdlibRegistry;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano.ProofCompressed;

/** Opt-in disposable local Yaci runner. Never prints or writes wallet keys or mnemonics. */
public final class AllowlistDevnet {
    private static final ObjectMapper JSON=new ObjectMapper();
    private static final Path FIXTURE=Path.of("bindings/js/build/circuit/allowlist_d1");
    private static final Path OUT=Path.of("bindings/cardano/build/evidence");
    private static final HttpClient HTTP=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private static URI local(String value) {
        URI uri=URI.create(value);
        if(!"http".equals(uri.getScheme())||!List.of("localhost","127.0.0.1","[::1]").contains(uri.getHost())
                ||uri.getUserInfo()!=null||uri.getQuery()!=null||uri.getFragment()!=null)
            throw new IllegalArgumentException("This demonstration accepts loopback HTTP endpoints only");
        return uri;
    }
    private static final URI STORE=local(System.getenv().getOrDefault("YACI_STORE_URL","http://localhost:8080/api/v1/"));
    private static final URI FAUCET=local(System.getenv().getOrDefault("YACI_FAUCET_URL","http://localhost:10000/local-cluster/api/addresses/topup"));
    private static final BFBackendService BACKEND=new BFBackendService(STORE.toString(),"local-devnet");
    private static void write(String name,Object value) throws Exception {
        Files.writeString(OUT.resolve(name),JSON.writerWithDefaultPrettyPrinter().writeValueAsString(value));
    }
    private static String hash(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    private static JsonNode read(String name) throws Exception {return JSON.readTree(Files.readString(FIXTURE.resolve(name)));}
    private static void header(JsonNode node) {
        String curve=node.path("curve").asText().toLowerCase().replace("-","").replace("_","");
        if(!"groth16".equals(node.path("protocol").asText())||!"bls12381".equals(curve))
            throw new IllegalArgumentException("Expected Groth16 BLS12-381 fixture");
    }
    private static ListPlutusData datum(BigInteger root) {var d=new ListPlutusData();d.add(BigIntPlutusData.of(root));return d;}
    private static ConstrPlutusData claim(ProofCompressed p,int action) {
        return ConstrPlutusData.of(0,BigIntPlutusData.of(action),BytesPlutusData.of(p.piA()),BytesPlutusData.of(p.piB()),BytesPlutusData.of(p.piC()));
    }
    private static ScriptTx spend(Utxo input,ProofCompressed p,int action,Account account,PlutusV3Script script,int ada) {
        return new ScriptTx().collectFrom(input,claim(p,action)).payToAddress(account.baseAddress(),Amount.ada(ada)).attachSpendingValidator(script);
    }
    private static void confirmed(String hash) throws Exception {
        for(int i=0;i<45;i++){if(BACKEND.getTransactionService().getTransaction(hash).isSuccessful())return;Thread.sleep(1000);}
        throw new IllegalStateException("Transaction confirmation timeout: "+hash);
    }
    public static void main(String[] args) throws Exception {
        if(args.length!=1||!args[0].equals("--local-devnet"))throw new IllegalArgumentException("Run explicitly with --local-devnet; development fixtures only");
        Files.createDirectories(OUT);
        var paramsResponse=HTTP.send(HttpRequest.newBuilder(STORE.resolve("epochs/latest/parameters")).timeout(Duration.ofSeconds(10)).GET().build(),HttpResponse.BodyHandlers.ofString());
        if(paramsResponse.statusCode()!=200)throw new IllegalStateException("Local protocol parameters unavailable");
        var params=JSON.readTree(paramsResponse.body());write("protocol-parameters.json",params);
        // This evaluator profile was validated for this local node version. Never silently switch targets.
        if(params.path("protocol_major_ver").asInt()!=11)throw new IllegalStateException("This experimental runner requires local protocol major 11");
        var manifest=JSON.readTree(Files.readString(FIXTURE.getParent().resolve("manifest.json")));
        JsonNode selected=null;for(var item:manifest)if(item.path("name").asText().equals("allowlist_d1"))selected=item;
        if(selected==null||!selected.path("developmentOnly").asBoolean()||!selected.path("proofSupported").asBoolean())
            throw new IllegalStateException("Regenerate development fixtures and browser proofs first");
        JsonNode browser=read("chromium-proof.json"),alternate=read("unapproved-root-proof.json"),vkJson=read("vk.json");
        header(browser.path("proof"));header(alternate.path("proof"));header(vkJson);
        var publicInputs=SnarkjsToCardano.parsePublicInputs(browser.path("publicInputs").toString());
        var otherInputs=SnarkjsToCardano.parsePublicInputs(alternate.path("publicInputs").toString());
        if(publicInputs.size()!=1||otherInputs.size()!=1)throw new IllegalArgumentException("Expected one root");
        BigInteger root=new BigInteger(read("inputs.json").path("root").asText());
        if(!publicInputs.getFirst().equals(root)||otherInputs.getFirst().equals(root))throw new IllegalStateException("Fixture root mismatch");
        var vk=SnarkjsToCardano.parseVk(vkJson.toString());if(vk.ic().size()!=2)throw new IllegalArgumentException("VK layout mismatch");
        var proof=SnarkjsToCardano.parseProof(browser.path("proof").toString());
        var otherProof=SnarkjsToCardano.parseProof(alternate.path("proof").toString());
        var account=new Account(Networks.testnet());byte[] pkh=account.hdKeyPair().getPublicKey().getKeyHash();
        String library=Files.readString(Path.of("zeroj-onchain-julc/src/main/java/org/zeroj/onchain/julc/groth16/lib/Groth16BLS12381Lib.java"));
        String source=Files.readString(Path.of("bindings/cardano/src/validators/AllowlistValidator.java"));
        var compiled=new JulcCompiler(StdlibRegistry.defaultRegistry()).compile(source,List.of(library));
        if(compiled.hasErrors())throw new IllegalStateException(compiled.diagnostics().toString());
        var applied=compiled.program().applyParams(PlutusData.bytes(vk.alpha()),PlutusData.bytes(vk.beta()),PlutusData.bytes(vk.gamma()),PlutusData.bytes(vk.delta()),
                PlutusData.list(vk.ic().stream().map(PlutusData::bytes).toArray(PlutusData[]::new)),PlutusData.integer(root),PlutusData.bytes(pkh));
        var script=JulcScriptAdapter.fromProgram(applied);
        var address=AddressProvider.getEntAddress(script,Networks.testnet()).toBech32();
        var funding=HTTP.send(HttpRequest.newBuilder(FAUCET).timeout(Duration.ofSeconds(15)).header("Content-Type","application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(Map.of("address",account.baseAddress(),"adaAmount",100))))
                .build(),HttpResponse.BodyHandlers.ofString());
        if(funding.statusCode()!=200)throw new IllegalStateException("Local faucet failed");Thread.sleep(3000);
        var txb=new QuickTxBuilder(BACKEND);
        var lockTx=txb.compose(new Tx().payToContract(address,Amount.ada(5),datum(root))
                .payToContract(address,Amount.ada(5),datum(otherInputs.getFirst())).from(account.baseAddress()))
                .withSigner(SignerProviders.signerFrom(account)).buildAndSign();
        var lock=BACKEND.getTransactionService().submitTransaction(lockTx.serialize());
        if(!lock.isSuccessful())throw new IllegalStateException(lock.toString());confirmed(lock.getValue());
        var utxos=BACKEND.getUtxoService().getUtxos(address,100,1).getValue();
        Utxo input=utxos.stream().filter(u->u.getTxHash().equals(lock.getValue())&&u.getOutputIndex()==0).findFirst().orElseThrow();
        Utxo other=utxos.stream().filter(u->u.getTxHash().equals(lock.getValue())&&u.getOutputIndex()==1).findFirst().orElseThrow();
        var evaluator=new JulcTransactionEvaluator(new DefaultUtxoSupplier(BACKEND.getUtxoService()),new DefaultProtocolParamsSupplier(BACKEND.getEpochService()),new DefaultScriptSupplier(BACKEND.getScriptService()));
        var tx=txb.compose(spend(input,proof,1,account,script,4)).withRequiredSigners(pkh).withTxEvaluator(evaluator)
                .withSigner(SignerProviders.signerFrom(account)).feePayer(account.baseAddress()).collateralPayer(account.baseAddress()).buildAndSign();
        byte[] bytes=tx.serialize();var local=evaluator.evaluateTx(bytes,Set.of(input));var remote=BACKEND.getTransactionService().evaluateTx(bytes);
        if(!local.isSuccessful()||!remote.isSuccessful())throw new IllegalStateException(local+" / "+remote);
        var budget=local.getValue().getFirst().getExUnits();
        if(!budget.equals(remote.getValue().getFirst().getExUnits()))throw new AssertionError("Java/remote budget mismatch");
        write("transaction.json",Map.of("type","Tx ConwayEra","description","Browser allowlist local demonstration","cborHex",HexFormat.of().formatHex(bytes)));
        var process=new ProcessBuilder("docker","exec","-i",System.getenv().getOrDefault("CARDANO_CONTAINER","node1-yaci-cli-1"),
                "/app/cardano-bin/cardano-cli","conway","transaction","calculate-plutus-script-cost","online","--testnet-magic","42",
                "--socket-path","/clusters/nodes/default/node/node.sock","--tx-file","/dev/stdin")
                .redirectErrorStream(true).redirectOutput(OUT.resolve("haskell-cost.json").toFile()).start();
        try(var stdin=process.getOutputStream()){stdin.write(Files.readAllBytes(OUT.resolve("transaction.json")));}
        if(!process.waitFor(30,TimeUnit.SECONDS)){process.destroyForcibly();throw new IllegalStateException("Haskell evaluation timeout");}
        if(process.exitValue()!=0)throw new IllegalStateException("Haskell evaluation failed");
        var haskell=JSON.readTree(Files.readString(OUT.resolve("haskell-cost.json"))).get(0).get("executionUnits");
        if(!haskell.get("steps").bigIntegerValue().equals(budget.getSteps())||!haskell.get("memory").bigIntegerValue().equals(budget.getMem()))
            throw new AssertionError("Haskell/Java budget mismatch");
        byte[] changed=proof.piA().clone();changed[0]^=0x20;
        var invalid=new ProofCompressed(changed,proof.piB(),proof.piC());
        var negatives=new LinkedHashMap<String,Object>();
        for(String name:List.of("unapproved_root_valid_proof","wrong_action","missing_required_signer","tampered_proof")){
            var composition=txb.compose(spend(name.equals("unapproved_root_valid_proof")?other:input,
                    name.equals("unapproved_root_valid_proof")?otherProof:name.equals("tampered_proof")?invalid:proof,
                    name.equals("wrong_action")?2:1,account,script,4)).withTxEvaluator((cbor,ins)->local)
                    .withSigner(SignerProviders.signerFrom(account)).feePayer(account.baseAddress()).collateralPayer(account.baseAddress());
            if(!name.equals("missing_required_signer"))composition.withRequiredSigners(pkh);
            byte[] bad=composition.buildAndSign().serialize();
            var eval=BACKEND.getTransactionService().evaluateTx(bad);
            if(eval.isSuccessful())throw new AssertionError(name+" accepted by evaluator");
            var submit=BACKEND.getTransactionService().submitTransaction(bad);
            if(submit.isSuccessful()||!submit.toString().contains("ValidationTagMismatch"))throw new AssertionError(name+": expected phase-2 rejection: "+submit);
            negatives.put(name,Map.of("evaluationRejected",true,"signedSubmissionRejected",true,"reason","ValidationTagMismatch"));
        }
        // Build a DIFFERENT transaction ID consuming the same UTxO before it is spent. A duplicate
        // submission of identical bytes can be idempotent and is not a meaningful replay test.
        byte[] replay=txb.compose(spend(input,proof,1,account,script,3)).withRequiredSigners(pkh).withTxEvaluator((cbor,ins)->local)
                .withSigner(SignerProviders.signerFrom(account)).feePayer(account.baseAddress()).collateralPayer(account.baseAddress()).buildAndSign().serialize();
        var submitted=BACKEND.getTransactionService().submitTransaction(bytes);
        if(!submitted.isSuccessful())throw new IllegalStateException(submitted.toString());confirmed(submitted.getValue());
        var replayResult=BACKEND.getTransactionService().submitTransaction(replay);
        String replayReason=replayResult.toString().contains("All inputs are spent")?"ConwayMempoolFailure: All inputs are spent":
                replayResult.toString().contains("BadInputsUTxO")?"BadInputsUTxO":null;
        if(replayResult.isSuccessful()||replayReason==null)throw new AssertionError("Expected spent-input rejection: "+replayResult);
        negatives.put("same_utxo_different_transaction",Map.of("signedSubmissionRejected",true,"reason",replayReason));
        var report=new LinkedHashMap<String,Object>();
        report.put("timestamp",Instant.now().toString());report.put("browserProofSha256",hash(Files.readAllBytes(FIXTURE.resolve("chromium-proof.json"))));
        report.put("verificationKeySha256",hash(Files.readAllBytes(FIXTURE.resolve("vk.json"))));report.put("validatorSourceSha256",hash(source.getBytes(StandardCharsets.UTF_8)));
        report.put("graphSha256",selected.path("graphSha256").asText());report.put("fingerprint",selected.path("fingerprint").asText());
        report.put("appliedFlatBytes",UplcFlatEncoder.encodeProgram(applied).length);report.put("scriptCborBytes",script.getCborHex().length()/2);
        report.put("compressedProofBytes",192);report.put("transactionBytes",bytes.length);report.put("cpuSteps",budget.getSteps());report.put("memoryUnits",budget.getMem());
        report.put("declaredCpuSteps",tx.getWitnessSet().getRedeemers().getFirst().getExUnits().getSteps());
        report.put("declaredMemoryUnits",tx.getWitnessSet().getRedeemers().getFirst().getExUnits().getMem());
        BigDecimal exFee=new BigDecimal(params.get("price_step").asText()).multiply(new BigDecimal(budget.getSteps()))
                .add(new BigDecimal(params.get("price_mem").asText()).multiply(new BigDecimal(budget.getMem())));
        report.put("executionFeeLovelace",exFee.setScale(0,RoundingMode.CEILING).toBigIntegerExact());report.put("feeLovelace",tx.getBody().getFee());
        report.put("lockFeeLovelace",lockTx.getBody().getFee());report.put("transactionHash",submitted.getValue());report.put("lockTransactionHash",lock.getValue());
        report.put("confirmed",true);report.put("javaRemoteHaskellBudgetsIdentical",true);report.put("negativeChecks",negatives);
        report.put("scope","Local PV11 development setup; pinned root, signer and action; reusable membership, no nullifier or anonymous authorization");
        write("result.json",report);System.out.println(JSON.writerWithDefaultPrettyPrinter().writeValueAsString(report));
    }
}
