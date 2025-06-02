"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decryptMessageNode = exports.NACK_REASONS = exports.MISSING_KEYS_ERROR_TEXT = exports.NO_MESSAGE_FOUND_ERROR_TEXT = void 0;
exports.decodeMessageNode = decodeMessageNode;
const boom_1 = require("@hapi/boom");
const WAProto_1 = require("../../WAProto");
const WABinary_1 = require("../WABinary");
const generics_1 = require("./generics");
const crypto_1 = require("./crypto");
const crypto_2 = require("crypto");
exports.NO_MESSAGE_FOUND_ERROR_TEXT = 'Message absent from node';
exports.MISSING_KEYS_ERROR_TEXT = 'Key used already or never filled';
const BOT_MESSAGE_CONSTANT = "Bot Message";
const KEY_LENGTH = 32;
exports.NACK_REASONS = {
    ParsingError: 487,
    UnrecognizedStanza: 488,
    UnrecognizedStanzaClass: 489,
    UnrecognizedStanzaType: 490,
    InvalidProtobuf: 491,
    InvalidHostedCompanionStanza: 493,
    MissingMessageSecret: 495,
    SignalErrorOldCounter: 496,
    MessageDeletedOnPeer: 499,
    UnhandledError: 500,
    UnsupportedAdminRevoke: 550,
    UnsupportedLIDGroup: 551,
    DBOperationFailed: 552
};
const deriveMessageSecret = async (messageSecret) => {
    // Always convert to Buffer to ensure compatibility
    const secretBuffer = Buffer.isBuffer(messageSecret)
        ? messageSecret
        : Buffer.from(messageSecret.buffer, messageSecret.byteOffset, messageSecret.length);
    return await (0, crypto_1.hkdf)(secretBuffer, KEY_LENGTH, { info: BOT_MESSAGE_CONSTANT });
};
const buildDecryptionKey = async (messageID, botJID, targetJID, messageSecret) => {
    const derivedSecret = await deriveMessageSecret(messageSecret);
    const useCaseSecret = Buffer.concat([
        Buffer.from(messageID),
        Buffer.from(targetJID),
        Buffer.from(botJID),
        Buffer.from("")
    ]);
    return await (0, crypto_1.hkdf)(derivedSecret, KEY_LENGTH, { info: useCaseSecret });
};
const decryptBotMessage = async (encPayload, encIv, messageID, botJID, decryptionKey) => {
    encPayload = Buffer.isBuffer(encPayload) ? encPayload : Buffer.from(encPayload);
    encIv = Buffer.isBuffer(encIv) ? encIv : Buffer.from(encIv);
    decryptionKey = Buffer.isBuffer(decryptionKey) ? decryptionKey : Buffer.from(decryptionKey);
    if (encIv.length !== 12) {
        throw new Error(`IV size incorrect: expected 12, got ${encIv.length}`);
    }
    const authTag = encPayload.slice(-16);
    const encryptedData = encPayload.slice(0, -16);
    if (encryptedData.length < 16) {
        throw new Error(`Encrypted data too short: ${encryptedData.length} bytes`);
    }
    const aad = Buffer.concat([
        Buffer.from(messageID),
        Buffer.from([0]),
        Buffer.from(botJID)
    ]);
    try {
        const decipher = (0, crypto_2.createDecipheriv)("aes-256-gcm", decryptionKey, encIv);
        decipher.setAAD(aad);
        decipher.setAuthTag(authTag);
        const decrypted = Buffer.concat([
            decipher.update(encryptedData),
            decipher.final()
        ]);
        return decrypted;
    }
    catch (error) {
        console.error("Decrypt - Failed with:", error.message);
        throw error;
    }
};
const decryptMsmsgBotMessage = async (messageSecret, messageKey, msMsg) => {
    try {
        const { targetId, participant: botJID, meId: targetJID } = messageKey;
        if (!targetId || !botJID || !targetJID || !messageSecret) {
            throw new Error("Missing required components for decryption");
        }
        const decryptionKey = await buildDecryptionKey(targetId, botJID, targetJID, messageSecret);
        if (!msMsg.encPayload) {
            throw new Error('Missing encPayload');
        }
        if (!msMsg.encIv) {
            throw new Error('Missing encIv');
        }
        return await decryptBotMessage(msMsg.encPayload, msMsg.encIv, targetId, botJID, decryptionKey);
    }
    catch (error) {
        console.error("Failed to decrypt bot message:", error);
        throw error;
    }
};
const decryptBotMsg = async (content, { messageKey, messageSecret }) => {
    try {
        const msMsg = WAProto_1.proto.MessageSecretMessage.decode(content);
        return await decryptMsmsgBotMessage(messageSecret, messageKey, msMsg);
    }
    catch (error) {
        console.error("Error in decryptBotMsg:", error);
        throw error;
    }
};
/**
 * Decode the received node as a message.
 * @note this will only parse the message, not decrypt it
 */
function decodeMessageNode(stanza, meId, meLid) {
    var _a, _b, _c, _d;
    let msgType;
    let chatId;
    let author;
    let userLid;
    const msgId = stanza.attrs.id;
    const from = stanza.attrs.from;
    const participant = stanza.attrs.participant;
    const participantLid = stanza.attrs.participant_lid;
    const recipient = stanza.attrs.recipient;
    const peerRecipientLid = stanza.attrs.peer_recipient_lid;
    const senderLid = stanza.attrs.sender_lid;
    const isMe = (jid) => (0, WABinary_1.areJidsSameUser)(jid, meId);
    const isMeLid = (jid) => (0, WABinary_1.areJidsSameUser)(jid, meLid);
    if ((0, WABinary_1.isJidMetaAI)(from) || (0, WABinary_1.isJidUser)(from) || (0, WABinary_1.isLidUser)(from)) {
        if (recipient && !(0, WABinary_1.isJidMetaAI)(recipient)) {
            if (!isMe(from) && !isMeLid(from)) {
                throw new boom_1.Boom('receipient present, but msg not from me', { data: stanza });
            }
            chatId = recipient;
            userLid = peerRecipientLid;
        }
        else {
            chatId = from;
            userLid = senderLid;
        }
        msgType = 'chat';
        author = from;
    }
    else if ((0, WABinary_1.isJidGroup)(from)) {
        if (!participant) {
            throw new boom_1.Boom('No participant in group message');
        }
        msgType = 'group';
        author = participant;
        chatId = from;
        userLid = participantLid;
    }
    else if ((0, WABinary_1.isJidNewsletter)(from)) {
        msgType = 'newsletter';
        author = from;
        chatId = from;
    }
    else if ((0, WABinary_1.isJidBroadcast)(from)) {
        if (!participant) {
            throw new boom_1.Boom('No participant in broadcast message');
        }
        const isParticipantMe = isMe(participant);
        if ((0, WABinary_1.isJidStatusBroadcast)(from)) {
            msgType = isParticipantMe ? 'direct_peer_status' : 'other_status';
        }
        else {
            msgType = isParticipantMe ? 'peer_broadcast' : 'other_broadcast';
        }
        chatId = from;
        author = participant;
        userLid = participantLid;
    }
    else {
        throw new boom_1.Boom('Unknown message type', { data: stanza });
    }
    const fromMe = (0, WABinary_1.isJidNewsletter)(from) ? !!((_a = stanza.attrs) === null || _a === void 0 ? void 0 : _a.is_sender) || false : ((0, WABinary_1.isLidUser)(from) ? isMeLid : isMe)(stanza.attrs.participant || stanza.attrs.from);
    const pushname = (_b = stanza === null || stanza === void 0 ? void 0 : stanza.attrs) === null || _b === void 0 ? void 0 : _b.notify;
    const key = {
        remoteJid: chatId,
        fromMe,
        id: msgId,
        participant,
        lid: userLid,
        'server_id': (_c = stanza.attrs) === null || _c === void 0 ? void 0 : _c.server_id
    };
    const fullMessage = {
        key,
        messageTimestamp: +stanza.attrs.t,
        pushName: pushname,
        broadcast: (0, WABinary_1.isJidBroadcast)(from)
    };
    if (msgType === 'newsletter') {
        fullMessage.newsletterServerId = +((_d = stanza.attrs) === null || _d === void 0 ? void 0 : _d.server_id);
    }
    if (key.fromMe) {
        fullMessage.status = WAProto_1.proto.WebMessageInfo.Status.SERVER_ACK;
    }
    return {
        fullMessage,
        author,
        sender: msgType === 'chat' ? author : chatId
    };
}
const decryptMessageNode = (stanza, meId, meLid, repository, logger, getMessage) => {
    const { fullMessage, author, sender } = decodeMessageNode(stanza, meId, meLid);
    let metaTargetId = null;
    let botEditTargetId = null;
    let botType = null;
    return {
        fullMessage,
        category: stanza.attrs.category,
        author,
        async decrypt() {
            var _a, _b;
            let decryptables = 0;
            if (Array.isArray(stanza.content)) {
                let hasMsmsg = false;
                for (const { attrs } of stanza.content) {
                    if ((attrs === null || attrs === void 0 ? void 0 : attrs.type) === 'msmsg') {
                        hasMsmsg = true;
                        break;
                    }
                }
                if (hasMsmsg) {
                    for (const { tag, attrs } of stanza.content) {
                        if (tag === 'meta' && (attrs === null || attrs === void 0 ? void 0 : attrs.target_id)) {
                            metaTargetId = attrs.target_id;
                        }
                        if (tag === 'bot' && (attrs === null || attrs === void 0 ? void 0 : attrs.edit_target_id)) {
                            botEditTargetId = attrs.edit_target_id;
                        }
                        if (tag === 'bot' && (attrs === null || attrs === void 0 ? void 0 : attrs.edit)) {
                            botType = attrs.edit;
                        }
                    }
                }
                for (const { tag, attrs, content } of stanza.content) {
                    if (tag === 'verified_name' && content instanceof Uint8Array) {
                        const cert = WAProto_1.proto.VerifiedNameCertificate.decode(content);
                        const details = WAProto_1.proto.VerifiedNameCertificate.Details.decode(cert.details);
                        fullMessage.verifiedBizName = details.verifiedName;
                    }
                    if (tag !== 'enc' && tag !== 'plaintext') {
                        continue;
                    }
                    if (!(content instanceof Uint8Array)) {
                        continue;
                    }
                    decryptables += 1;
                    let msgBuffer;
                    try {
                        const e2eType = tag === 'plaintext' ? 'plaintext' : attrs.type;
                        switch (e2eType) {
                            case 'skmsg':
                                msgBuffer = await repository.decryptGroupMessage({
                                    group: sender,
                                    authorJid: author,
                                    msg: content
                                });
                                break;
                            case 'pkmsg':
                            case 'msg':
                                const user = (0, WABinary_1.isJidUser)(sender) ? sender : author;
                                msgBuffer = await repository.decryptMessage({
                                    jid: user,
                                    type: e2eType,
                                    ciphertext: content
                                });
                                break;
                            case 'msmsg':
                                let msgRequestkey = {
                                    remoteJid: stanza.attrs.from,
                                    id: metaTargetId
                                };
                                const message = await getMessage(msgRequestkey);
                                const messageSecret = (_a = message === null || message === void 0 ? void 0 : message.messageContextInfo) === null || _a === void 0 ? void 0 : _a.messageSecret;
                                if (!messageSecret) {
                                    throw new Error('Message secret not found');
                                }
                                // Only decrypts when it is the complete message
                                if (botType == 'last') {
                                    const newkey = {
                                        participant: stanza.attrs.from,
                                        meId: stanza.attrs.from.endsWith(`@bot`) ?
                                            `${meLid.split(`:`)[0]}@lid` :
                                            `${meId.split(`:`)[0]}@s.whatsapp.net`,
                                        targetId: botEditTargetId
                                    };
                                    msgBuffer = await decryptBotMsg(content, {
                                        messageKey: newkey,
                                        messageSecret
                                    });
                                }
                                else
                                    return;
                                break;
                            case 'plaintext':
                                msgBuffer = content;
                                break;
                            case undefined:
                                msgBuffer = content;
                                break;
                            default:
                                throw new Error(`Unknown e2e type: ${e2eType}`);
                        }
                        let msg = WAProto_1.proto.Message.decode(e2eType !== 'plaintext' && !hasMsmsg ? (0, generics_1.unpadRandomMax16)(msgBuffer) : msgBuffer);
                        // It's necessary to save the messageContextInfo in the store to decrypt messages from bots
                        msg = ((_b = msg.deviceSentMessage) === null || _b === void 0 ? void 0 : _b.message) ? { ...msg.deviceSentMessage.message, messageContextInfo: msg.messageContextInfo } : msg;
                        if (msg.senderKeyDistributionMessage) {
                            try {
                                await repository.processSenderKeyDistributionMessage({
                                    authorJid: author,
                                    item: msg.senderKeyDistributionMessage
                                });
                            }
                            catch (err) {
                                logger.error({ key: fullMessage.key, err }, 'failed to decrypt message');
                            }
                        }
                        if (fullMessage.message) {
                            Object.assign(fullMessage.message, msg);
                        }
                        else {
                            fullMessage.message = msg;
                        }
                    }
                    catch (err) {
                        logger.error({ key: fullMessage.key, err }, 'failed to decrypt message');
                        fullMessage.messageStubType = WAProto_1.proto.WebMessageInfo.StubType.CIPHERTEXT;
                        fullMessage.messageStubParameters = [err.message];
                    }
                }
            }
            // if nothing was found to decrypt
            if (!decryptables) {
                fullMessage.messageStubType = WAProto_1.proto.WebMessageInfo.StubType.CIPHERTEXT;
                fullMessage.messageStubParameters = [exports.NO_MESSAGE_FOUND_ERROR_TEXT];
            }
        }
    };
};
exports.decryptMessageNode = decryptMessageNode;
