package org.zeroj.bindings.threshold;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import org.zeroj.bindings.common.*;
import org.zeroj.bindings.elgamal.ElGamalAdapter;
import org.zeroj.circuit.lib.jubjub.*;

/** Protocol participant state. The host must authenticate channels and agree round closure. */
public final class ThresholdAdapter implements Adapter {
    private static final class ParticipantState {
        final DkgParticipant participant;
        final Set<String> received = new HashSet<>();
        boolean failed;
        ParticipantState(DkgParticipant participant) { this.participant=participant; }
        void requireLive() { if(failed)throw new BindingException("PROTOCOL_RESOURCE_LIMIT"); }
    }
    @Override public JsonNode invoke(String op, JsonNode a, BindingSession s) {
        return switch(op) {
            case "configure" -> {
                Boundary.fields(a,"faults","roster","applicationContext","attempt");
                JsonNode roster=a.get("roster");
                if(roster==null||!roster.isArray()||roster.size()<3||roster.size()>16)throw Boundary.invalid();
                var keys=new ArrayList<byte[]>();
                for(var key:roster) keys.add(Boundary.bytes(Boundary.object().set("key",key),"key",1,4096));
                var config=DkgConfig.create(Boundary.integer(a,"faults",1,7),keys.size(),keys,
                        Boundary.bytes(a,"applicationContext",0,4096),Boundary.scalar(a,"attempt",BigInteger.ONE.shiftLeft(64)).longValue());
                yield Boundary.object().put("handle",s.retain(config)).put("session",Boundary.hex(config.session()));
            }
            case "createParticipant" -> {
                Boundary.fields(a,"config","participantId");s.requireSecrets();
                var config=s.get(Boundary.text(a,"config"),DkgConfig.class);
                var participant=DkgParticipant.create(config,Boundary.integer(a,"participantId",1,config.n()),s.random());
                yield Boundary.object().put("handle",s.retain(new ParticipantState(participant)));
            }
            case "start", "closeRound" -> {
                Boundary.fields(a,"participant");s.requireSecrets();
                var state=state(a,s);var participant=state.participant;
                var outgoing=op.equals("start")?participant.start():participant.closeRound();
                state.received.clear();yield messages(outgoing,participant.openRound());
            }
            case "receiveBroadcast", "receivePrivate" -> {
                Boundary.fields(a,"participant","authenticatedSender","message");s.requireSecrets();
                var state=state(a,s);var p=state.participant;int sender=Boundary.integer(a,"authenticatedSender",1,16);
                byte[] message=Boundary.bytes(a,"message",36,4096);
                String identity=op+":"+sender+":"+Boundary.hex(message);
                if(!state.received.contains(identity)) {
                    if(state.received.size()>=1024) {state.failed=true;throw new BindingException("PROTOCOL_RESOURCE_LIMIT");}
                    if(op.equals("receiveBroadcast"))p.receiveBroadcast(sender,message);else p.receivePrivate(sender,message);
                    state.received.add(identity);
                }
                yield Boundary.object().put("round",p.openRound());
            }
            case "result" -> {
                Boundary.fields(a,"participant");s.requireSecrets();
                var key=state(a,s).participant.result();var context=key.context();
                var out=Boundary.object().put("key",s.retain(key)).put("context",s.retain(context))
                        .put("participantId",key.id()).put("publicKey",Boundary.hex(context.jointKey().encode()))
                        .put("transcriptDigest",Boundary.hex(context.transcriptDigest())).put("requiredShares",context.threshold()+1);
                var qualified=out.putArray("qualified");context.qual().forEach(qualified::add);yield out;
            }
            case "decryptionShare" -> {
                Boundary.fields(a,"key","ciphertext");s.requireSecrets();
                yield ElGamalAdapter.share(s,ElGamal.decryptionShare(s.get(Boundary.text(a,"key"),ThresholdKeyShare.class),ElGamalAdapter.cipher(a,s)));
            }
            default -> throw new BindingException("UNSUPPORTED_OPERATION");
        };
    }
    private static ParticipantState state(JsonNode a, BindingSession s) {
        var state=s.get(Boundary.text(a,"participant"),ParticipantState.class);state.requireLive();return state;
    }
    private static JsonNode messages(List<DkgMessage> messages, int round) {
        var out=Boundary.object().put("round",round);var array=out.putArray("messages");
        for(var message:messages)array.add(Boundary.object().put("bytes",Boundary.hex(message.encode()))
                .put("channel",message.kind()==DkgMessage.Kind.SHARE?"private":"broadcast")
                .put("sender",message.sender()).put("recipient",message.subject()).put("kind",message.kind().name()));
        return out;
    }
}
