#!/usr/bin/env node

import crypto from "node:crypto";
import dns from "node:dns/promises";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import {fileURLToPath} from "node:url";

const MANIFEST_SCHEMA = "true-family-pass-b1a-manifest-v1";
const RUNTIME_SCHEMA = "true-family-pass-b1a-runtime-v1";
const FAILURE_SCHEMA = "true-family-pass-b1a-runtime-failure-v2";
const CONTROL_REQUEST_TOPIC = "$CONTROL/dynamic-security/v1";
const CONTROL_RESPONSE_TOPIC = "$CONTROL/dynamic-security/v1/response";
const GATEWAY_POLICY_SCHEMA = "true-family-pass-b1a-gateway-policy-v1";
const GATEWAY_STARTUP_SCHEMA = "true-family-pass-b1a-gateway-startup-v1";
const MAX_PACKET_BYTES = 1024 * 1024;
const MAX_INPUT_JSON_BYTES = 1024 * 1024;
const MAX_STREAM_BYTES = 2 * 1024 * 1024;
const MAX_PROPERTY_BYTES = 64 * 1024;
const MAX_PROPERTIES = 64;
const IO_TIMEOUT_MS = 5_000;
const NO_DELIVERY_MS = 250;
const GATEWAY_HANDSHAKE_TIMEOUT_MS = 5_000;
const GATEWAY_IDLE_TIMEOUT_MS = 30_000;
const MQTT_KEEPALIVE_SECONDS = 300;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const PASSWORD_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const BOUNDARY_WHITESPACE_PATTERN = /^[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]|[\u0009-\u000d\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]$/u;
const FRONTEND_PRINCIPALS = Object.freeze(["z2m", "orchestrator", "collector", "other"]);

class B1AFailure extends Error {
    constructor(code) {
        super(code);
        this.code = code;
    }
}

class B1AClientBeforeFailure extends Error {
    constructor(category) {
        super("client_before_failure");
        this.category = category;
    }
}

const INSTALL_FAILURE_CATEGORIES = Object.freeze([
    "context", "credentials", "broker_connect", "broker_subscribe",
    "command_transport", "command_rejected", "security", "unknown",
]);
const CLIENT_BEFORE_FAILURE_CATEGORIES = Object.freeze([
    "network", "authentication", "publish_matrix", "subscribe_matrix",
    "source_privacy", "retained_control", "unknown",
]);
const RUNTIME_FAILURE_CATEGORIES = Object.freeze([...new Set([
    ...INSTALL_FAILURE_CATEGORIES,
    ...CLIENT_BEFORE_FAILURE_CATEGORIES,
])]);
const INSTALL_FAILURE_CATEGORY_BY_CODE = Object.freeze({
    runtime_environment: "context",
    runtime_mode: "context",
    runtime_endpoint: "context",
    manifest_json: "context",
    manifest_identity: "context",
    manifest_classification: "context",
    manifest_scope: "context",
    manifest_preflight_acl: "context",
    manifest_artifact: "context",
    runtime_gateway_policy: "context",
    runtime_output_size: "context",
    admin_credentials_json: "credentials",
    admin_credential_shape: "credentials",
    admin_credential_schema: "credentials",
    credential_shape: "credentials",
    credential_identity: "credentials",
    frontend_credential_shape: "credentials",
    frontend_credential_schema: "credentials",
    frontend_credential_principals: "credentials",
    observer_credential_shape: "credentials",
    observer_credential_schema: "credentials",
    credential_uniqueness: "credentials",
    install_password_uniqueness: "credentials",
    control_connect: "broker_connect",
    principal_connect: "broker_connect",
    control_subscribe: "broker_subscribe",
    subscribe_closed: "broker_subscribe",
    suback_shape: "broker_subscribe",
    suback_packetid: "broker_subscribe",
    suback_reasons: "broker_subscribe",
    suback_reason: "broker_subscribe",
    control_correlation_shape: "command_transport",
    control_correlation_unique: "command_transport",
    control_puback: "command_transport",
    control_response_json: "command_transport",
    control_response_shape: "command_transport",
    control_response_count: "command_transport",
    control_response_identity: "command_transport",
    mqtt_timeout: "command_transport",
    message_closed: "command_transport",
    unexpected_packet: "command_transport",
    control_response_error: "command_rejected",
    container_security: "security",
});

export function installFailureCategoryForCode(code) {
    return typeof code === "string" && Object.hasOwn(INSTALL_FAILURE_CATEGORY_BY_CODE, code)
        ? INSTALL_FAILURE_CATEGORY_BY_CODE[code]
        : "unknown";
}

export function runtimeFailureCategory(mode, error) {
    if (mode === "install" && error instanceof B1AFailure) return installFailureCategoryForCode(error.code);
    if (
        mode === "client_before"
        && error instanceof B1AClientBeforeFailure
        && CLIENT_BEFORE_FAILURE_CATEGORIES.includes(error.category)
    ) return error.category;
    return "unknown";
}

export function runtimeFailureRecord(category) {
    const safe = RUNTIME_FAILURE_CATEGORIES.includes(category) ? category : "unknown";
    return `${canonical({schema: FAILURE_SCHEMA, result: "fail", failure_category: safe})}\n`;
}

async function runClientBeforePhase(category, operation) {
    gate(CLIENT_BEFORE_FAILURE_CATEGORIES.includes(category) && category !== "unknown" && typeof operation === "function", "client_before_phase");
    try {
        return await operation();
    } catch (error) {
        if (error instanceof B1AFailure) throw new B1AClientBeforeFailure(category);
        throw error;
    }
}

function gate(condition, code) {
    if (!condition) throw new B1AFailure(code);
}

function exactKeys(value, keys, code) {
    gate(value !== null && typeof value === "object" && !Array.isArray(value), code);
    gate(JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()), code);
}

export function canonical(value) {
    if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) return `[${value.map((item) => canonical(item)).join(",")}]`;
    gate(value && typeof value === "object", "canonical_type");
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

function same(left, right) {
    return canonical(left) === canonical(right);
}

function compareStrings(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}

export function sha256Bytes(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

function readJson(file, code) {
    try {
        const bytes = fs.readFileSync(file);
        gate(bytes.length > 0 && bytes.length <= MAX_INPUT_JSON_BYTES, code);
        const text = bytes.toString("utf8");
        gate(Buffer.from(text, "utf8").equals(bytes), code);
        return JSON.parse(text);
    } catch (error) {
        if (error instanceof B1AFailure) throw error;
        throw new B1AFailure(code);
    }
}

function readPrivateJson(file, code) {
    const metadata = fs.lstatSync(file);
    gate(
        metadata.isFile()
        && !metadata.isSymbolicLink()
        && metadata.nlink === 1
        && (metadata.mode & 0o777) === 0o600
        && metadata.size > 0
        && metadata.size <= MAX_INPUT_JSON_BYTES,
        code,
    );
    const handle = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try {
        const opened = fs.fstatSync(handle);
        gate(opened.dev === metadata.dev && opened.ino === metadata.ino && opened.size === metadata.size, code);
        const bytes = fs.readFileSync(handle);
        const text = bytes.toString("utf8");
        gate(Buffer.from(text, "utf8").equals(bytes), code);
        return JSON.parse(text);
    } finally {
        fs.closeSync(handle);
    }
}

function validMqttText(value) {
    if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value, "utf8") > 0xffff) return false;
    for (const character of value) {
        const codepoint = character.codePointAt(0);
        if (
            codepoint <= 0x1f
            || (codepoint >= 0x7f && codepoint <= 0x9f)
            || (codepoint >= 0xd800 && codepoint <= 0xdfff)
            || (codepoint >= 0xfdd0 && codepoint <= 0xfdef)
            || (codepoint & 0xffff) === 0xfffe
            || (codepoint & 0xffff) === 0xffff
        ) return false;
    }
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const low = value.charCodeAt(index + 1);
            if (!(low >= 0xdc00 && low <= 0xdfff)) return false;
            index += 1;
        } else if (code >= 0xdc00 && code <= 0xdfff) return false;
    }
    return true;
}

function u16(value) {
    gate(Number.isInteger(value) && value >= 0 && value <= 0xffff, "u16");
    const result = Buffer.alloc(2);
    result.writeUInt16BE(value);
    return result;
}

function u32(value) {
    gate(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, "u32");
    const result = Buffer.alloc(4);
    result.writeUInt32BE(value);
    return result;
}

function mqttString(value) {
    gate(validMqttText(value), "mqtt_utf8");
    const bytes = Buffer.from(value, "utf8");
    gate(bytes.length <= 0xffff, "mqtt_utf8_length");
    return Buffer.concat([u16(bytes.length), bytes]);
}

function mqttBinary(value) {
    const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
    gate(bytes.length <= 0xffff, "mqtt_binary_length");
    return Buffer.concat([u16(bytes.length), bytes]);
}

export function encodeVarInt(value) {
    gate(Number.isInteger(value) && value >= 0 && value <= 268_435_455, "varint_range");
    const bytes = [];
    do {
        let encoded = value % 128;
        value = Math.floor(value / 128);
        if (value > 0) encoded |= 0x80;
        bytes.push(encoded);
    } while (value > 0);
    return Buffer.from(bytes);
}

function tryDecodeVarInt(buffer, offset = 0) {
    gate(Buffer.isBuffer(buffer) && Number.isInteger(offset) && offset >= 0 && offset <= buffer.length, "varint_input");
    let multiplier = 1;
    let value = 0;
    for (let index = 0; index < 4; index += 1) {
        if (offset + index >= buffer.length) return null;
        const byte = buffer[offset + index];
        value += (byte & 0x7f) * multiplier;
        gate(value <= 268_435_455, "varint_range");
        if ((byte & 0x80) === 0) {
            const bytes = index + 1;
            gate(encodeVarInt(value).length === bytes, "varint_noncanonical");
            return {value, bytes};
        }
        multiplier *= 128;
    }
    throw new B1AFailure("varint_overlong");
}

export function decodeVarInt(buffer, offset = 0) {
    const decoded = tryDecodeVarInt(buffer, offset);
    gate(decoded !== null, "varint_truncated");
    return decoded;
}

function packet(type, flags, body) {
    gate(Number.isInteger(type) && type >= 1 && type <= 15 && Number.isInteger(flags) && flags >= 0 && flags <= 15, "packet_type");
    gate(Buffer.isBuffer(body) && body.length <= MAX_PACKET_BYTES, "packet_size");
    return Buffer.concat([Buffer.from([(type << 4) | flags]), encodeVarInt(body.length), body]);
}

export function parsePacketFrame(frame) {
    gate(Buffer.isBuffer(frame) && frame.length >= 2 && frame.length <= MAX_PACKET_BYTES + 5, "frame_size");
    const remaining = decodeVarInt(frame, 1);
    const bodyOffset = 1 + remaining.bytes;
    gate(bodyOffset + remaining.value === frame.length, "frame_length");
    const type = frame[0] >> 4;
    const flags = frame[0] & 0x0f;
    const fixedFlags = [0, 0, 0, undefined, 0, 0, 2, 0, 2, 0, 2, 0, 0, 0, 0, 0];
    gate(type >= 1 && type <= 15 && (type === 3 || flags === fixedFlags[type]), "frame_flags");
    return {type, flags, body: frame.subarray(bodyOffset)};
}

function readU16(buffer, cursor, end, code) {
    gate(cursor.offset + 2 <= end, code);
    const value = buffer.readUInt16BE(cursor.offset);
    cursor.offset += 2;
    return value;
}

function readU32(buffer, cursor, end, code) {
    gate(cursor.offset + 4 <= end, code);
    const value = buffer.readUInt32BE(cursor.offset);
    cursor.offset += 4;
    return value;
}

function readMqttString(buffer, cursor, end, code) {
    const length = readU16(buffer, cursor, end, code);
    gate(cursor.offset + length <= end, code);
    const bytes = buffer.subarray(cursor.offset, cursor.offset + length);
    cursor.offset += length;
    const value = bytes.toString("utf8");
    gate(Buffer.from(value, "utf8").equals(bytes) && validMqttText(value), code);
    return value;
}

function readMqttBinary(buffer, cursor, end, code) {
    const length = readU16(buffer, cursor, end, code);
    gate(cursor.offset + length <= end, code);
    const value = buffer.subarray(cursor.offset, cursor.offset + length);
    cursor.offset += length;
    return Buffer.from(value);
}

export function parseProperties(buffer, offset, end) {
    const length = decodeVarInt(buffer, offset);
    gate(length.value <= MAX_PROPERTY_BYTES, "properties_size");
    const cursor = {offset: offset + length.bytes};
    const propertyEnd = cursor.offset + length.value;
    gate(propertyEnd <= end, "properties_truncated");
    const values = [];
    while (cursor.offset < propertyEnd) {
        gate(values.length < MAX_PROPERTIES, "properties_count");
        const identifier = decodeVarInt(buffer, cursor.offset);
        cursor.offset += identifier.bytes;
        let value;
        switch (identifier.value) {
            case 0x01:
            case 0x17:
            case 0x19:
            case 0x24:
            case 0x25:
            case 0x28:
            case 0x29:
            case 0x2a:
                gate(cursor.offset + 1 <= propertyEnd, "property_value");
                value = buffer[cursor.offset];
                cursor.offset += 1;
                break;
            case 0x02:
            case 0x11:
            case 0x18:
            case 0x27:
                value = readU32(buffer, cursor, propertyEnd, "property_value");
                break;
            case 0x13:
            case 0x21:
            case 0x22:
            case 0x23:
                value = readU16(buffer, cursor, propertyEnd, "property_value");
                break;
            case 0x0b: {
                const variable = decodeVarInt(buffer, cursor.offset);
                cursor.offset += variable.bytes;
                value = variable.value;
                break;
            }
            case 0x03:
            case 0x08:
            case 0x12:
            case 0x15:
            case 0x1a:
            case 0x1c:
            case 0x1f:
                value = readMqttString(buffer, cursor, propertyEnd, "property_value");
                break;
            case 0x09:
            case 0x16:
                value = readMqttBinary(buffer, cursor, propertyEnd, "property_value");
                break;
            case 0x26:
                value = [
                    readMqttString(buffer, cursor, propertyEnd, "property_value"),
                    readMqttString(buffer, cursor, propertyEnd, "property_value"),
                ];
                break;
            default:
                throw new B1AFailure("property_identifier");
        }
        values.push({identifier: identifier.value, value});
    }
    gate(cursor.offset === propertyEnd, "properties_length");
    return {values, offset: propertyEnd};
}

export function encodeConnect({clientId, username, password, cleanStart = true, sessionExpiry = 0}) {
    gate(validMqttText(clientId), "connect_clientid");
    gate((username === undefined) === (password === undefined), "connect_auth_shape");
    let flags = cleanStart ? 0x02 : 0;
    const payload = [mqttString(clientId)];
    if (username !== undefined) {
        gate(validMqttText(username) && typeof password === "string", "connect_auth");
        flags |= 0xc0;
        payload.push(mqttString(username), mqttBinary(Buffer.from(password, "utf8")));
    }
    const properties = sessionExpiry > 0
        ? Buffer.concat([Buffer.from([0x11]), u32(sessionExpiry)])
        : Buffer.alloc(0);
    const variable = Buffer.concat([
        mqttString("MQTT"),
        Buffer.from([5, flags]),
        u16(MQTT_KEEPALIVE_SECONDS),
        encodeVarInt(properties.length),
        properties,
    ]);
    return packet(1, 0, Buffer.concat([variable, ...payload]));
}

export function parseConnack(body) {
    gate(Buffer.isBuffer(body) && body.length >= 3, "connack_shape");
    const flags = body[0];
    const reason = body[1];
    gate((flags & 0xfe) === 0, "connack_flags");
    const properties = parseProperties(body, 2, body.length);
    gate(properties.offset === body.length, "connack_length");
    return {sessionPresent: Boolean(flags & 1), reason, properties: properties.values};
}

export function encodeSubscribe(packetId, filters) {
    gate(Array.isArray(filters) && filters.length > 0 && filters.length <= 32, "subscribe_filters");
    const payload = [];
    for (const item of filters) {
        gate(item && validMqttText(item.filter) && Number.isInteger(item.qos) && item.qos >= 0 && item.qos <= 2, "subscribe_filter");
        payload.push(mqttString(item.filter), Buffer.from([item.qos]));
    }
    return packet(8, 2, Buffer.concat([u16(packetId), Buffer.from([0]), ...payload]));
}

export function parseSuback(body) {
    gate(Buffer.isBuffer(body) && body.length >= 4, "suback_shape");
    const cursor = {offset: 0};
    const packetId = readU16(body, cursor, body.length, "suback_packetid");
    gate(packetId > 0, "suback_packetid");
    const properties = parseProperties(body, cursor.offset, body.length);
    cursor.offset = properties.offset;
    gate(cursor.offset < body.length, "suback_reasons");
    const reasons = [...body.subarray(cursor.offset)];
    gate(reasons.every((reason) => [0, 1, 2, 0x80, 0x83, 0x87, 0x8f, 0x91, 0x97, 0x9e, 0xa1, 0xa2].includes(reason)), "suback_reason");
    return {packetId, reasons, properties: properties.values};
}

export function encodePublish(topic, payload, {qos = 1, retain = false, duplicate = false, packetId = 1, properties = []} = {}) {
    gate(validMqttText(topic) && !topic.includes("+") && !topic.includes("#"), "publish_topic");
    gate(Number.isInteger(qos) && qos >= 0 && qos <= 2 && typeof retain === "boolean" && typeof duplicate === "boolean" && (qos > 0 || duplicate === false), "publish_options");
    const propertyBytes = [];
    for (const property of properties) {
        if (property.identifier === 0x08) propertyBytes.push(Buffer.from([0x08]), mqttString(property.value));
        else if (property.identifier === 0x09) propertyBytes.push(Buffer.from([0x09]), mqttBinary(property.value));
        else throw new B1AFailure("publish_property");
    }
    const variable = [mqttString(topic)];
    if (qos > 0) variable.push(u16(packetId));
    const encodedProperties = Buffer.concat(propertyBytes);
    variable.push(encodeVarInt(encodedProperties.length), encodedProperties);
    const body = Buffer.concat([...variable, Buffer.isBuffer(payload) ? payload : Buffer.from(payload)]);
    return packet(3, (duplicate ? 8 : 0) | (qos << 1) | (retain ? 1 : 0), body);
}

export function encodeUncheckedPublish(topic, payload, {qos = 1, retain = false, packetId = 1} = {}) {
    gate(typeof topic === "string" && Number.isInteger(qos) && [0, 1, 2].includes(qos) && typeof retain === "boolean", "unchecked_publish");
    const topicBytes = Buffer.from(topic, "utf8");
    gate(topicBytes.length <= 0xffff, "unchecked_publish");
    const variable = [u16(topicBytes.length), topicBytes];
    if (qos > 0) variable.push(u16(packetId));
    variable.push(Buffer.from([0]));
    return packet(3, (qos << 1) | (retain ? 1 : 0), Buffer.concat([...variable, Buffer.isBuffer(payload) ? payload : Buffer.from(payload)]));
}

function encodeRawTopicPublish(topicBytes, payload, {qos = 1, retain = false, packetId = 1} = {}) {
    gate(Buffer.isBuffer(topicBytes) && topicBytes.length <= 0xffff && [0, 1, 2].includes(qos) && typeof retain === "boolean", "raw_publish");
    const variable = [u16(topicBytes.length), topicBytes];
    if (qos > 0) variable.push(u16(packetId));
    variable.push(Buffer.from([0]));
    return packet(3, (qos << 1) | (retain ? 1 : 0), Buffer.concat([...variable, Buffer.isBuffer(payload) ? payload : Buffer.from(payload)]));
}

function encodeRawFilterSubscribe(packetId, filterBytes) {
    gate(Number.isInteger(packetId) && packetId > 0 && Buffer.isBuffer(filterBytes) && filterBytes.length <= 0xffff, "raw_subscribe");
    return packet(8, 2, Buffer.concat([u16(packetId), Buffer.from([0]), u16(filterBytes.length), filterBytes, Buffer.from([1])]));
}

export function parsePublish(flags, body) {
    const qos = (flags >> 1) & 0x03;
    gate(qos <= 2, "publish_qos");
    gate(qos > 0 || (flags & 8) === 0, "publish_duplicate");
    const cursor = {offset: 0};
    const topic = readMqttString(body, cursor, body.length, "publish_topic");
    gate(!topic.includes("+") && !topic.includes("#"), "publish_topic");
    let packetId;
    if (qos > 0) {
        packetId = readU16(body, cursor, body.length, "publish_packetid");
        gate(packetId > 0, "publish_packetid");
    }
    const properties = parseProperties(body, cursor.offset, body.length);
    cursor.offset = properties.offset;
    return {
        topic,
        payload: Buffer.from(body.subarray(cursor.offset)),
        qos,
        retain: Boolean(flags & 1),
        duplicate: Boolean(flags & 8),
        packetId,
        properties: properties.values,
    };
}

function parsePublishAck(body, code, allowedReasons) {
    gate(Buffer.isBuffer(body) && body.length >= 2, `${code}_shape`);
    const cursor = {offset: 0};
    const packetId = readU16(body, cursor, body.length, `${code}_packetid`);
    gate(packetId > 0, `${code}_packetid`);
    if (cursor.offset === body.length) return {packetId, reason: 0, properties: []};
    const reason = body[cursor.offset];
    cursor.offset += 1;
    gate(allowedReasons.includes(reason), `${code}_reason`);
    if (cursor.offset === body.length) return {packetId, reason, properties: []};
    const properties = parseProperties(body, cursor.offset, body.length);
    gate(properties.offset === body.length, `${code}_length`);
    return {packetId, reason, properties: properties.values};
}

export function parsePuback(body) {
    return parsePublishAck(body, "puback", [0, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99]);
}

export function parsePubrec(body) {
    return parsePublishAck(body, "pubrec", [0, 0x10, 0x80, 0x83, 0x87, 0x90, 0x91, 0x97, 0x99]);
}

export function parsePubrel(body) {
    return parsePublishAck(body, "pubrel", [0, 0x92]);
}

export function parsePubcomp(body) {
    return parsePublishAck(body, "pubcomp", [0, 0x92]);
}

export function encodeUnsubscribe(packetId, filters) {
    gate(Array.isArray(filters) && filters.length > 0, "unsubscribe_filters");
    return packet(10, 2, Buffer.concat([u16(packetId), Buffer.from([0]), ...filters.map(mqttString)]));
}

export function parseUnsuback(body) {
    gate(Buffer.isBuffer(body) && body.length >= 4, "unsuback_shape");
    const cursor = {offset: 0};
    const packetId = readU16(body, cursor, body.length, "unsuback_packetid");
    gate(packetId > 0, "unsuback_packetid");
    const properties = parseProperties(body, cursor.offset, body.length);
    cursor.offset = properties.offset;
    gate(cursor.offset < body.length, "unsuback_reasons");
    const reasons = [...body.subarray(cursor.offset)];
    gate(reasons.every((reason) => [0, 0x11, 0x80, 0x83, 0x87, 0x8f, 0x91].includes(reason)), "unsuback_reason");
    return {packetId, reasons, properties: properties.values};
}

function requireNoProperties(values, code) {
    gate(Array.isArray(values) && values.length === 0, code);
}

export function parseConnectFrame(frame) {
    const parsed = parsePacketFrame(frame);
    gate(parsed.type === 1 && parsed.flags === 0, "connect_packet");
    const cursor = {offset: 0};
    const protocol = readMqttString(parsed.body, cursor, parsed.body.length, "connect_protocol");
    gate(protocol === "MQTT" && cursor.offset + 4 <= parsed.body.length, "connect_protocol");
    const level = parsed.body[cursor.offset];
    const flags = parsed.body[cursor.offset + 1];
    cursor.offset += 2;
    gate(level === 5 && (flags & 0x3d) === 0, "connect_flags");
    const hasUsername = Boolean(flags & 0x80);
    const hasPassword = Boolean(flags & 0x40);
    gate(hasUsername === hasPassword, "connect_auth_shape");
    const keepalive = readU16(parsed.body, cursor, parsed.body.length, "connect_keepalive");
    const properties = parseProperties(parsed.body, cursor.offset, parsed.body.length);
    cursor.offset = properties.offset;
    gate(properties.values.every((item) => item.identifier === 0x11) && properties.values.length <= 1, "connect_properties");
    const clientId = readMqttString(parsed.body, cursor, parsed.body.length, "connect_clientid");
    let username;
    let passwordLength = 0;
    if (hasUsername) {
        username = readMqttString(parsed.body, cursor, parsed.body.length, "connect_username");
        passwordLength = readU16(parsed.body, cursor, parsed.body.length, "connect_password");
        gate(passwordLength > 0 && passwordLength <= 1024 && cursor.offset + passwordLength <= parsed.body.length, "connect_password");
        cursor.offset += passwordLength;
    }
    gate(cursor.offset === parsed.body.length, "connect_length");
    return {
        clientId,
        username,
        passwordPresent: hasPassword,
        cleanStart: Boolean(flags & 0x02),
        keepalive,
        sessionExpiry: properties.values.find((item) => item.identifier === 0x11)?.value ?? 0,
    };
}

export function parseSubscribe(body) {
    const cursor = {offset: 0};
    const packetId = readU16(body, cursor, body.length, "subscribe_packetid");
    gate(packetId > 0, "subscribe_packetid");
    const properties = parseProperties(body, cursor.offset, body.length);
    cursor.offset = properties.offset;
    requireNoProperties(properties.values, "subscribe_properties");
    const filters = [];
    while (cursor.offset < body.length) {
        gate(filters.length < 32, "subscribe_count");
        const filter = readMqttString(body, cursor, body.length, "subscribe_filter");
        gate(cursor.offset < body.length, "subscribe_options");
        const options = body[cursor.offset];
        cursor.offset += 1;
        gate((options & 0xfc) === 0 && (options & 0x03) <= 2, "subscribe_options");
        filters.push({filter, qos: options & 0x03});
    }
    gate(filters.length > 0, "subscribe_count");
    return {packetId, filters};
}

export function parseUnsubscribe(body) {
    const cursor = {offset: 0};
    const packetId = readU16(body, cursor, body.length, "unsubscribe_packetid");
    gate(packetId > 0, "unsubscribe_packetid");
    const properties = parseProperties(body, cursor.offset, body.length);
    cursor.offset = properties.offset;
    requireNoProperties(properties.values, "unsubscribe_properties");
    const filters = [];
    while (cursor.offset < body.length) {
        gate(filters.length < 32, "unsubscribe_count");
        filters.push(readMqttString(body, cursor, body.length, "unsubscribe_filter"));
    }
    gate(filters.length > 0, "unsubscribe_count");
    return {packetId, filters};
}

export function parseDisconnect(body) {
    const allowedReasons = new Set([
        0x00, 0x04, 0x80, 0x81, 0x82, 0x83, 0x87, 0x89, 0x8b, 0x8d, 0x8e,
        0x8f, 0x90, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
        0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2,
    ]);
    if (body.length === 0) return {reason: 0};
    const reason = body[0];
    gate(allowedReasons.has(reason), "disconnect_reason");
    if (body.length === 1) return {reason};
    const properties = parseProperties(body, 1, body.length);
    gate(properties.offset === body.length, "disconnect_length");
    gate(properties.values.every((item) => [0x11, 0x1c, 0x1f, 0x26].includes(item.identifier)), "disconnect_properties");
    for (const identifier of [0x11, 0x1c, 0x1f]) gate(properties.values.filter((item) => item.identifier === identifier).length <= 1, "disconnect_properties");
    return {reason, properties: properties.values};
}

export class MqttFrameStream {
    constructor() {
        this.buffer = Buffer.alloc(0);
    }

    push(chunk) {
        gate(Buffer.isBuffer(chunk) && chunk.length > 0, "stream_chunk");
        gate(this.buffer.length + chunk.length <= MAX_STREAM_BYTES, "stream_buffer_size");
        this.buffer = Buffer.concat([this.buffer, chunk]);
        const frames = [];
        while (this.buffer.length >= 2) {
            const remaining = tryDecodeVarInt(this.buffer, 1);
            if (remaining === null) break;
            const total = 1 + remaining.bytes + remaining.value;
            gate(total <= MAX_PACKET_BYTES + 5, "stream_packet_size");
            if (this.buffer.length < total) break;
            const frame = Buffer.from(this.buffer.subarray(0, total));
            parsePacketFrame(frame);
            frames.push(frame);
            const remainder = this.buffer.subarray(total);
            this.buffer = remainder.length === 0 ? Buffer.alloc(0) : Buffer.from(remainder);
        }
        return frames;
    }
}

export function gatewayConnectBatchIsIsolated(frames, stream) {
    return Array.isArray(frames) && frames.length === 1 && stream instanceof MqttFrameStream && stream.buffer.length === 0;
}

export function gatewayBackendConnectMayForward(state, clientDestroyed) {
    return state === "connecting_backend" && clientDestroyed === false;
}

export function gatewayPreConnackBufferIsEmpty(readableLength) {
    return Number.isInteger(readableLength) && readableLength === 0;
}

export function topicContractValid(value) {
    if (!validMqttText(value) || [...value].length > 256) return false;
    if (value.startsWith("/") || value.endsWith("/") || value.includes("+") || value.includes("#")) return false;
    if (BOUNDARY_WHITESPACE_PATTERN.test(value)) return false;
    return true;
}

export function containsBridgeRequest(value) {
    const segments = value.split("/");
    return segments.some((segment, index) => segment === "bridge" && segments[index + 1] === "request");
}

function mqttFilterStructurallyValid(value) {
    if (!validMqttText(value) || [...value].length > 256 || value.startsWith("/") || value.endsWith("/") || BOUNDARY_WHITESPACE_PATTERN.test(value)) return false;
    if (value.startsWith("$share/")) return false;
    const levels = value.split("/");
    return levels.every((level, index) => {
        if (level.includes("#")) return level === "#" && index === levels.length - 1;
        if (level.includes("+")) return level === "+";
        return true;
    });
}

export function gatewayPolicyProjection(manifest) {
    return {
        schema: GATEWAY_POLICY_SCHEMA,
        generation: 1,
        base_topic: manifest.scope.base_topic,
        topic_contract: manifest.preflight_acl.effective_policy.topic_contract,
        identities: Object.fromEntries(FRONTEND_PRINCIPALS.map((key) => [key, {
            username: manifest.principals[key].username,
            client_id: manifest.principals[key].client_id,
        }])),
        frontend_denied: ["admin", "observer", "unknown", "anonymous"],
        orchestrator: {
            publish: manifest.topics.request_topics.map((topic) => ({topic, qos: 1, retain: false})),
            subscribe: [manifest.topics.ready, manifest.topics.status, manifest.topics.result, manifest.topics.response, manifest.topics.ack_response],
        },
        zigbee2mqtt: {
            publish: "any-contract-valid-except-adjacent-bridge-request",
            publish_qos: [0, 1, 2],
            publish_retain: [false, true],
            subscribe: [`${manifest.scope.base_topic}/#`, "any-contract-valid-concrete-topic"],
            subscribe_qos: [0, 1, 2],
            shared_subscriptions: false,
        },
        collector: {
            publish: [],
            subscribe: [manifest.topics.status, manifest.topics.result, manifest.topics.response, manifest.topics.ack_response],
            test_only: true,
        },
        other: {publish: [], subscribe: []},
        transport: {
            mqtt_version: 5,
            qos2_proxy_stateful: true,
            handshake_timeout_ms: GATEWAY_HANDSHAKE_TIMEOUT_MS,
            idle_timeout_ms: GATEWAY_IDLE_TIMEOUT_MS,
            bidirectional_backpressure: true,
            broker_ack_authority: true,
        },
        assurances: {
            credential_files_provisioned: false,
            artifact_files_provisioned: false,
            connect_password_in_transit: true,
            connect_password_decoded: false,
            connect_password_persisted: false,
            broker_ack_authority: true,
            gateway_enforcement: true,
            broker_origin_malformed_latches_gateway: true,
            composite_policy: true,
        },
    };
}

export function gatewayPolicyDigest(manifest) {
    return sha256Bytes(Buffer.from(canonical(gatewayPolicyProjection(manifest)), "utf8"));
}

function frontendPrincipalForConnect(manifest, connect) {
    if (!connect.username || !connect.passwordPresent) return undefined;
    return FRONTEND_PRINCIPALS.find((key) => {
        const principal = manifest.principals[key];
        return connect.username === principal.username && connect.clientId === principal.client_id;
    });
}

export function gatewayAllowsPublish(manifest, principal, {topic, qos, retain}) {
    if (!topicContractValid(topic) || !Number.isInteger(qos) || ![0, 1, 2].includes(qos) || typeof retain !== "boolean") return false;
    if (principal === "orchestrator") return manifest.topics.request_topics.includes(topic) && qos === 1 && retain === false;
    if (principal === "z2m") return !containsBridgeRequest(topic);
    return false;
}

export function gatewayAllowsSubscribe(manifest, principal, filter) {
    if (!mqttFilterStructurallyValid(filter)) return false;
    if (principal === "z2m") return filter === `${manifest.scope.base_topic}/#` || topicContractValid(filter);
    if (!topicContractValid(filter)) return false;
    if (principal === "orchestrator") return [manifest.topics.ready, manifest.topics.status, manifest.topics.result, manifest.topics.response, manifest.topics.ack_response].includes(filter);
    if (principal === "collector") return [manifest.topics.status, manifest.topics.result, manifest.topics.response, manifest.topics.ack_response].includes(filter);
    return false;
}

function qos2State() {
    return {clientPublishes: new Map(), brokerPublishes: new Map()};
}

function publicationPropertyIdentity(properties) {
    return canonical(properties.map((item) => ({
        identifier: item.identifier,
        value: Buffer.isBuffer(item.value)
            ? {binary_base64: item.value.toString("base64")}
            : item.value,
    })));
}

function publicationIdentity(publication) {
    return Object.freeze({
        topic: publication.topic,
        qos: publication.qos,
        retain: publication.retain,
        packetId: publication.packetId,
        properties: publicationPropertyIdentity(publication.properties),
        payload_base64: publication.payload.toString("base64"),
    });
}

function publicationIdentityMatches(identity, publication) {
    return identity.topic === publication.topic
        && identity.qos === publication.qos
        && identity.retain === publication.retain
        && identity.packetId === publication.packetId
        && identity.properties === publicationPropertyIdentity(publication.properties)
        && identity.payload_base64 === publication.payload.toString("base64");
}

function beginQos2(map, publication, code) {
    const previous = map.get(publication.packetId);
    if (previous?.state === "completed") {
        gate(publication.duplicate === false, `${code}_stale`);
        map.set(publication.packetId, {state: "await_pubrec", identity: publicationIdentity(publication)});
        return;
    }
    if (previous === undefined) {
        gate(publication.duplicate === false, `${code}_stale`);
        if (map.size >= 32) {
            const completed = [...map].find(([, value]) => value.state === "completed");
            gate(completed !== undefined, `${code}_count`);
            map.delete(completed[0]);
        }
        map.set(publication.packetId, {state: "await_pubrec", identity: publicationIdentity(publication)});
        return;
    }
    gate(publication.duplicate === true && ["await_pubrec", "await_pubrel"].includes(previous.state) && publicationIdentityMatches(previous.identity, publication), `${code}_duplicate`);
}

function rejectQosChangeDuringExchange(map, publication, code) {
    if (publication.qos !== 1) return;
    const previous = map.get(publication.packetId);
    gate(previous === undefined || previous.state === "completed", code);
    if (previous?.state === "completed") map.delete(publication.packetId);
}

function advanceQos2(map, packetId, expected, next, reason, code) {
    const previous = map.get(packetId);
    const succeeded = reason === 0 || reason === 0x10;
    if (expected === "await_pubrec" && previous?.state === "await_pubrel" && succeeded) return;
    gate(previous?.state === expected, `${code}_state`);
    if (succeeded) {
        if (next === undefined) map.set(packetId, {state: "completed", identity: previous.identity});
        else map.set(packetId, {state: next, identity: previous.identity});
    } else {
        map.set(packetId, {state: "completed", identity: previous.identity});
    }
}

function validateGatewayClientFrame(frame, manifest, principal, state = qos2State()) {
    const packetFrame = parsePacketFrame(frame);
    if (packetFrame.type === 3) {
        const publication = parsePublish(packetFrame.flags, packetFrame.body);
        gate(gatewayAllowsPublish(manifest, principal, publication), "gateway_publish_policy");
        if (publication.qos === 2) beginQos2(state.clientPublishes, publication, "gateway_client_qos2_publish");
        else rejectQosChangeDuringExchange(state.clientPublishes, publication, "gateway_client_qos_change");
        return {closing: false, type: 3};
    }
    if (packetFrame.type === 4) {
        parsePuback(packetFrame.body);
        return {closing: false, type: 4};
    }
    if (packetFrame.type === 5) {
        const ack = parsePubrec(packetFrame.body);
        advanceQos2(state.brokerPublishes, ack.packetId, "await_pubrec", "await_pubrel", ack.reason, "gateway_client_pubrec");
        return {closing: false, type: 5};
    }
    if (packetFrame.type === 6) {
        const ack = parsePubrel(packetFrame.body);
        advanceQos2(state.clientPublishes, ack.packetId, "await_pubrel", "await_pubcomp", ack.reason, "gateway_client_pubrel");
        return {closing: false, type: 6};
    }
    if (packetFrame.type === 7) {
        const ack = parsePubcomp(packetFrame.body);
        advanceQos2(state.brokerPublishes, ack.packetId, "await_pubcomp", undefined, ack.reason, "gateway_client_pubcomp");
        return {closing: false, type: 7};
    }
    if (packetFrame.type === 8) {
        const subscription = parseSubscribe(packetFrame.body);
        gate(subscription.filters.every((item) => gatewayAllowsSubscribe(manifest, principal, item.filter)), "gateway_subscribe_policy");
        return {closing: false, type: 8};
    }
    if (packetFrame.type === 10) {
        const unsubscribe = parseUnsubscribe(packetFrame.body);
        gate(unsubscribe.filters.every((filter) => gatewayAllowsSubscribe(manifest, principal, filter)), "gateway_unsubscribe_policy");
        return {closing: false, type: 10};
    }
    if (packetFrame.type === 12) {
        gate(packetFrame.body.length === 0, "gateway_pingreq");
        return {closing: false, type: 12};
    }
    if (packetFrame.type === 14) {
        parseDisconnect(packetFrame.body);
        return {closing: true, type: 14};
    }
    throw new B1AFailure("gateway_client_packet_unsupported");
}

function validateGatewayBrokerFrame(frame, state = qos2State()) {
    const packetFrame = parsePacketFrame(frame);
    if (packetFrame.type === 2) return {type: 2, value: parseConnack(packetFrame.body)};
    if (packetFrame.type === 3) {
        const publication = parsePublish(packetFrame.flags, packetFrame.body);
        if (publication.qos === 2) beginQos2(state.brokerPublishes, publication, "gateway_broker_qos2_publish");
        else rejectQosChangeDuringExchange(state.brokerPublishes, publication, "gateway_broker_qos_change");
        return {type: 3};
    }
    if (packetFrame.type === 4) {
        parsePuback(packetFrame.body);
        return {type: 4};
    }
    if (packetFrame.type === 5) {
        const ack = parsePubrec(packetFrame.body);
        advanceQos2(state.clientPublishes, ack.packetId, "await_pubrec", "await_pubrel", ack.reason, "gateway_broker_pubrec");
        return {type: 5};
    }
    if (packetFrame.type === 6) {
        const ack = parsePubrel(packetFrame.body);
        advanceQos2(state.brokerPublishes, ack.packetId, "await_pubrel", "await_pubcomp", ack.reason, "gateway_broker_pubrel");
        return {type: 6};
    }
    if (packetFrame.type === 7) {
        const ack = parsePubcomp(packetFrame.body);
        advanceQos2(state.clientPublishes, ack.packetId, "await_pubcomp", undefined, ack.reason, "gateway_broker_pubcomp");
        return {type: 7};
    }
    if (packetFrame.type === 9) {
        parseSuback(packetFrame.body);
        return {type: 9};
    }
    if (packetFrame.type === 11) {
        parseUnsuback(packetFrame.body);
        return {type: 11};
    }
    if (packetFrame.type === 13) {
        gate(packetFrame.body.length === 0, "gateway_pingresp");
        return {type: 13};
    }
    if (packetFrame.type === 14) {
        parseDisconnect(packetFrame.body);
        return {type: 14};
    }
    throw new B1AFailure("gateway_broker_packet_unsupported");
}

export function gatewayBackendDisconnectFatal({state, clientClosing, brokerClosing, clientDestroyed}) {
    return ["connecting_backend", "awaiting_connack", "active"].includes(state)
        && clientClosing === false
        && brokerClosing === false
        && clientDestroyed === false;
}

export function gatewayUpstreamErrorFatal(state) {
    return !["broker_denied", "closing", "rejected", "closed"].includes(state);
}

function writePrivateJson(file, value) {
    const bytes = Buffer.from(`${canonical(value)}\n`, "utf8");
    const handle = fs.openSync(file, "wx", 0o600);
    try {
        fs.writeFileSync(handle, bytes);
        fs.fsyncSync(handle);
        fs.fchmodSync(handle, 0o600);
    } finally {
        fs.closeSync(handle);
    }
    const metadata = fs.lstatSync(file);
    gate(metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1 && metadata.size === bytes.length && (metadata.mode & 0o777) === 0o600, "private_file_mode");
}

async function runGateway(manifest) {
    const listenHost = process.env.B1A_LISTEN_HOST;
    const listenPort = Number(process.env.B1A_LISTEN_PORT);
    const brokerHost = process.env.B1A_ENDPOINT_HOST;
    const brokerPort = Number(process.env.B1A_ENDPOINT_PORT);
    const statusPath = process.env.B1A_STATUS_PATH;
    gate(listenHost === "gateway" && listenPort === 18884 && brokerHost === "broker" && brokerPort === 18883, "gateway_environment");
    gate(typeof statusPath === "string" && statusPath.startsWith("/status/"), "gateway_status_path");
    const policyDigest = gatewayPolicyDigest(manifest);
    gate(policyDigest === manifest.gateway.policy_sha256, "gateway_policy_digest");
    const sessions = new Set();
    let latched = false;
    let shuttingDown = false;
    let server;

    const clearSessionTimer = (session) => {
        if (session.timer !== undefined) clearTimeout(session.timer);
        session.timer = undefined;
    };

    const rejectSession = (session) => {
        if (["rejected", "closed"].includes(session.state)) return;
        session.state = "rejected";
        clearSessionTimer(session);
        session.client.destroy();
        session.upstream?.destroy();
    };

    const armSessionTimer = (session, milliseconds) => {
        clearSessionTimer(session);
        session.timer = setTimeout(() => rejectSession(session), milliseconds);
        session.timer.unref();
    };

    const forwardFrame = (source, destination, frame, session) => {
        gate(destination.writable === true, "gateway_destination_writable");
        if (!destination.write(frame)) {
            source.pause();
            destination.once("drain", () => {
                if (["active", "closing"].includes(session.state) && !source.destroyed) source.resume();
            });
        }
    };

    const latch = () => {
        if (latched || shuttingDown) return;
        latched = true;
        for (const session of sessions) {
            clearSessionTimer(session);
            session.client.destroy();
            session.upstream?.destroy();
        }
        if (server?.listening) server.close();
    };

    server = net.createServer((client) => {
        if (latched || shuttingDown || sessions.size >= 32) {
            client.destroy();
            return;
        }
        const session = {
            client,
            upstream: undefined,
            clientStream: new MqttFrameStream(),
            brokerStream: new MqttFrameStream(),
            qos2: qos2State(),
            state: "awaiting_connect",
            clientClosing: false,
            brokerClosing: false,
            principal: undefined,
            timer: undefined,
        };
        sessions.add(session);
        armSessionTimer(session, GATEWAY_HANDSHAKE_TIMEOUT_MS);

        client.on("data", (chunk) => {
            try {
                const frames = session.clientStream.push(chunk);
                for (const frame of frames) {
                    if (session.state === "awaiting_connect") {
                        gate(gatewayConnectBatchIsIsolated(frames, session.clientStream), "gateway_connect_coalesced_application_data");
                        const connect = parseConnectFrame(frame);
                        const principal = frontendPrincipalForConnect(manifest, connect);
                        gate(principal !== undefined, "gateway_frontend_identity");
                        session.principal = principal;
                        session.state = "connecting_backend";
                        armSessionTimer(session, GATEWAY_HANDSHAKE_TIMEOUT_MS);
                        client.pause();
                        const upstream = net.createConnection({host: brokerHost, port: brokerPort});
                        session.upstream = upstream;
                        upstream.setNoDelay(true);
                        upstream.once("connect", () => {
                            if (!gatewayBackendConnectMayForward(session.state, client.destroyed)) {
                                upstream.destroy();
                                return;
                            }
                            session.state = "awaiting_connack";
                            armSessionTimer(session, GATEWAY_HANDSHAKE_TIMEOUT_MS);
                            forwardFrame(client, upstream, frame, session);
                        });
                        upstream.on("data", (brokerChunk) => {
                            try {
                                for (const brokerFrame of session.brokerStream.push(brokerChunk)) {
                                    const result = validateGatewayBrokerFrame(brokerFrame, session.qos2);
                                    if (session.state === "awaiting_connack") {
                                        gate(result.type === 2, "gateway_connack_first");
                                        if (result.value.reason === 0 && !gatewayPreConnackBufferIsEmpty(client.readableLength)) {
                                            rejectSession(session);
                                            return;
                                        }
                                        session.state = result.value.reason === 0 ? "active" : "broker_denied";
                                        forwardFrame(upstream, client, brokerFrame, session);
                                        if (session.state === "active") {
                                            armSessionTimer(session, GATEWAY_IDLE_TIMEOUT_MS);
                                            client.resume();
                                        } else {
                                            clearSessionTimer(session);
                                            client.end();
                                            upstream.end();
                                        }
                                    } else {
                                        gate(session.state === "active" || session.state === "closing", "gateway_broker_state");
                                        if (result.type === 14) session.brokerClosing = true;
                                        forwardFrame(upstream, client, brokerFrame, session);
                                        if (session.state === "active") armSessionTimer(session, GATEWAY_IDLE_TIMEOUT_MS);
                                    }
                                }
                            } catch {
                                latch();
                            }
                        });
                        upstream.on("error", () => {
                            if (gatewayUpstreamErrorFatal(session.state)) latch();
                        });
                        upstream.on("close", () => {
                            if (gatewayBackendDisconnectFatal({state: session.state, clientClosing: session.clientClosing, brokerClosing: session.brokerClosing, clientDestroyed: client.destroyed})) latch();
                            client.destroy();
                        });
                        continue;
                    }
                    gate(session.state === "active", "gateway_client_state");
                    const result = validateGatewayClientFrame(frame, manifest, session.principal, session.qos2);
                    if (result.closing) {
                        session.clientClosing = true;
                        session.state = "closing";
                        clearSessionTimer(session);
                    } else {
                        armSessionTimer(session, GATEWAY_IDLE_TIMEOUT_MS);
                    }
                    forwardFrame(client, session.upstream, frame, session);
                }
            } catch {
                rejectSession(session);
            }
        });
        client.on("error", () => rejectSession(session));
        client.on("end", () => {
            session.clientClosing = true;
            clearSessionTimer(session);
            if (!["closing", "rejected"].includes(session.state)) session.state = "closed";
            session.upstream?.end();
        });
        client.on("close", () => {
            session.clientClosing = true;
            clearSessionTimer(session);
            if (session.state !== "rejected") session.state = "closed";
            session.upstream?.end();
            sessions.delete(session);
        });
    });
    server.maxConnections = 32;
    const closed = new Promise((resolve) => server.once("close", resolve));
    await new Promise((resolve, reject) => {
        const onError = (error) => reject(error);
        server.once("error", onError);
        server.listen(listenPort, listenHost, () => {
            server.off("error", onError);
            resolve();
        });
    });
    server.on("error", latch);
    writePrivateJson(statusPath, {
        schema: GATEWAY_STARTUP_SCHEMA,
        result: "ready",
        generation: 1,
        policy_sha256: policyDigest,
        frontend_listener: 18884,
        backend_broker: "broker:18883",
        frontend_bound: true,
        credential_files_provisioned: false,
        artifact_files_provisioned: false,
        connect_password_in_transit: true,
        connect_password_decoded: false,
        connect_password_persisted: false,
        broker_ack_authority: true,
        gateway_enforcement: true,
        broker_origin_malformed_latches_gateway: true,
        composite_policy: true,
    });

    const shutdown = () => {
        if (shuttingDown) return;
        shuttingDown = true;
        for (const session of sessions) {
            session.clientClosing = true;
            clearSessionTimer(session);
            session.client.destroy();
            session.upstream?.destroy();
        }
        server.close();
    };
    process.once("SIGTERM", shutdown);
    process.once("SIGINT", shutdown);
    await closed;
    gate(!latched, "gateway_latched_failure");
    return undefined;
}

function encodePublishAck(type, packetId, reason = 0) {
    const flags = type === 6 ? 2 : 0;
    return packet(type, flags, reason === 0 ? u16(packetId) : Buffer.concat([u16(packetId), Buffer.from([reason])]));
}

function encodePuback(packetId, reason = 0) {
    return encodePublishAck(4, packetId, reason);
}

function encodePubrec(packetId, reason = 0) {
    return encodePublishAck(5, packetId, reason);
}

function encodePubrel(packetId, reason = 0) {
    return encodePublishAck(6, packetId, reason);
}

function encodePubcomp(packetId, reason = 0) {
    return encodePublishAck(7, packetId, reason);
}

function publishAckSucceeded(reason) {
    return reason === 0 || reason === 0x10;
}

export function publishResultSucceeded(result) {
    if (!result || typeof result !== "object") return false;
    if (result.qos === 2) return publishAckSucceeded(result.pubrec_reason) && result.pubcomp_reason === 0;
    return publishAckSucceeded(result.reason);
}

export function denialHistoryIsClean(history, startSequence) {
    const forbidden = new Set([2, 3, 4, 5, 6, 7, 9, 11]);
    return history.filter((item) => item.sequence > startSequence).every((item) => !forbidden.has(item.type));
}

function encodeDisconnect(reason = 0) {
    return reason === 0 ? packet(14, 0, Buffer.alloc(0)) : packet(14, 0, Buffer.from([reason, 0]));
}

function sleep(milliseconds) {
    return new Promise((resolve) => {
        const timer = setTimeout(resolve, milliseconds);
        timer.unref();
    });
}

function blockingDelay(milliseconds) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

class MqttClient {
    constructor(options) {
        this.options = options;
        this.socket = null;
        this.buffer = Buffer.alloc(0);
        this.events = [];
        this.waiters = new Set();
        this.packetId = 1;
        this.closed = false;
        this.sequence = 0;
        this.history = [];
        this.incomingQos2 = new Map();
        this.connectionPacketTypes = [];
    }

    _notify(event) {
        this.sequence += 1;
        event.sequence = this.sequence;
        this.history.push({sequence: event.sequence, type: event.type});
        if (this.history.length > 4096) this.history.splice(0, this.history.length - 4096);
        if (this.events.length >= 1024) {
            gate(event.type === "close", "mqtt_event_count");
            this.events.length = 0;
        }
        this.events.push(event);
        for (const notify of this.waiters) notify();
        this.waiters.clear();
    }

    _consume() {
        while (this.buffer.length >= 2) {
            const remaining = tryDecodeVarInt(this.buffer, 1);
            if (remaining === null) return;
            const total = 1 + remaining.bytes + remaining.value;
            gate(total <= MAX_PACKET_BYTES + 5, "stream_packet_size");
            if (this.buffer.length < total) return;
            const frame = this.buffer.subarray(0, total);
            this.buffer = this.buffer.subarray(total);
            const parsed = parsePacketFrame(frame);
            let event;
            if (parsed.type === 2) event = {type: 2, value: parseConnack(parsed.body)};
            else if (parsed.type === 3) {
                const value = parsePublish(parsed.flags, parsed.body);
                if (value.qos === 1) this.socket.write(encodePuback(value.packetId));
                if (value.qos === 2) {
                    const existing = this.incomingQos2.get(value.packetId);
                    gate(existing === undefined || (value.duplicate && publicationIdentityMatches(existing.identity, value)), "mqtt_incoming_qos2_duplicate");
                    if (existing === undefined) this.incomingQos2.set(value.packetId, {state: "await_pubrel", identity: publicationIdentity(value), value});
                    this.socket.write(encodePubrec(value.packetId));
                    continue;
                }
                event = {type: 3, value};
            } else if (parsed.type === 4) event = {type: 4, value: parsePuback(parsed.body)};
            else if (parsed.type === 5) event = {type: 5, value: parsePubrec(parsed.body)};
            else if (parsed.type === 6) {
                const value = parsePubrel(parsed.body);
                const pending = this.incomingQos2.get(value.packetId);
                gate(pending?.state === "await_pubrel", "mqtt_incoming_pubrel");
                this.incomingQos2.delete(value.packetId);
                this.socket.write(encodePubcomp(value.packetId));
                event = {type: 3, value: pending.value};
            }
            else if (parsed.type === 7) event = {type: 7, value: parsePubcomp(parsed.body)};
            else if (parsed.type === 9) event = {type: 9, value: parseSuback(parsed.body)};
            else if (parsed.type === 11) event = {type: 11, value: parseUnsuback(parsed.body)};
            else if (parsed.type === 13) {
                gate(parsed.body.length === 0, "pingresp");
                event = {type: 13};
            }
            else if (parsed.type === 14) event = {type: 14, value: parseDisconnect(parsed.body)};
            else throw new B1AFailure("unexpected_packet");
            this._notify(event);
        }
    }

    async _next(predicate, milliseconds = IO_TIMEOUT_MS, optional = false) {
        const deadline = Date.now() + milliseconds;
        while (true) {
            const index = this.events.findIndex(predicate);
            if (index >= 0) return this.events.splice(index, 1)[0];
            const remaining = deadline - Date.now();
            if (remaining <= 0) {
                if (optional) return null;
                throw new B1AFailure("mqtt_timeout");
            }
            await new Promise((resolve) => {
                const timer = setTimeout(() => {
                    this.waiters.delete(notify);
                    resolve();
                }, remaining);
                timer.unref();
                const notify = () => {
                    clearTimeout(timer);
                    resolve();
                };
                this.waiters.add(notify);
            });
        }
    }

    async open() {
        const {host, port} = this.options;
        this.socket = net.createConnection({host, port});
        this.socket.setNoDelay(true);
        this.socket.on("data", (chunk) => {
            try {
                gate(this.buffer.length + chunk.length <= MAX_PACKET_BYTES + 5, "stream_buffer_size");
                this.buffer = Buffer.concat([this.buffer, chunk]);
                this._consume();
            } catch {
                this.socket.destroy();
            }
        });
        this.socket.on("error", () => undefined);
        this.socket.on("close", () => {
            this.closed = true;
            this._notify({type: "close"});
        });
        const connection = await Promise.race([
            new Promise((resolve) => {
                this.socket.once("connect", () => resolve("connected"));
                this.socket.once("error", () => resolve("closed"));
                this.socket.once("close", () => resolve("closed"));
            }),
            sleep(IO_TIMEOUT_MS).then(() => "timeout"),
        ]);
        if (connection !== "connected") {
            this.socket.destroy();
            return {reason: "closed", sessionPresent: false, properties: []};
        }
        const startSequence = this.sequence;
        this.socket.write(encodeConnect(this.options));
        const event = await this._next((item) => item.type === 2 || item.type === "close");
        this.connectionPacketTypes = this.history.filter((item) => item.sequence > startSequence && item.type !== "close").map((item) => item.type);
        return event.type === 2 ? event.value : {reason: "closed", sessionPresent: false, properties: []};
    }

    nextPacketId() {
        const value = this.packetId;
        this.packetId = value === 0xffff ? 1 : value + 1;
        return value;
    }

    async subscribe(filters) {
        const packetId = this.nextPacketId();
        this.socket.write(encodeSubscribe(packetId, filters.map((filter) => typeof filter === "string" ? {filter, qos: 1} : filter)));
        const event = await this._next((item) => item.type === "close" || (item.type === 9 && item.value.packetId === packetId));
        gate(event.type === 9, "subscribe_closed");
        return event.value;
    }

    async unsubscribe(filters) {
        const packetId = this.nextPacketId();
        this.socket.write(encodeUnsubscribe(packetId, filters));
        const event = await this._next((item) => item.type === "close" || (item.type === 11 && item.value.packetId === packetId));
        gate(event.type === 11, "unsubscribe_closed");
        return event.value;
    }

    async publish(topic, payload, options = {}) {
        const qos = options.qos ?? 1;
        const packetId = qos > 0 ? this.nextPacketId() : 0;
        this.socket.write(encodePublish(topic, payload, {...options, qos, packetId}));
        if (qos === 0) return {reason: 0, packetId: 0, qos: 0};
        if (qos === 1) {
            const event = await this._next((item) => item.type === "close" || (item.type === 4 && item.value.packetId === packetId));
            return event.type === 4 ? {...event.value, qos} : {reason: "closed", packetId, qos};
        }
        const received = await this._next((item) => item.type === "close" || (item.type === 5 && item.value.packetId === packetId));
        if (received.type !== 5 || !publishAckSucceeded(received.value.reason)) {
            return received.type === 5
                ? {...received.value, qos, pubrec_reason: received.value.reason, pubcomp_reason: undefined}
                : {reason: "closed", packetId, qos, pubrec_reason: undefined, pubcomp_reason: undefined};
        }
        this.socket.write(encodePubrel(packetId));
        const completed = await this._next((item) => item.type === "close" || (item.type === 7 && item.value.packetId === packetId));
        return completed.type === 7
            ? {...completed.value, reason: completed.value.reason, pubrec_reason: received.value.reason, pubcomp_reason: completed.value.reason, qos}
            : {reason: "closed", packetId, qos, pubrec_reason: received.value.reason, pubcomp_reason: undefined};
    }

    async message(topic, milliseconds = IO_TIMEOUT_MS) {
        const event = await this._next((item) => item.type === "close" || (item.type === 3 && item.value.topic === topic), milliseconds);
        gate(event.type === 3, "message_closed");
        return event.value;
    }

    async noMessage(topic, milliseconds = NO_DELIVERY_MS) {
        const event = await this._next((item) => item.type === "close" || (item.type === 3 && item.value.topic === topic), milliseconds, true);
        gate(event === null, "unexpected_delivery");
        return true;
    }

    async sendAndExpectClose(frame, milliseconds = IO_TIMEOUT_MS) {
        gate(Buffer.isBuffer(frame) && this.socket?.writable === true, "gateway_denial_frame");
        const startSequence = this.sequence;
        this.socket.write(frame);
        const event = await this._next((item) => item.type === "close", milliseconds);
        gate(event.type === "close", "gateway_denial_close");
        gate(denialHistoryIsClean(this.history, startSequence), "gateway_denial_preceded_by_broker_output");
        return true;
    }

    async ping() {
        this.socket.write(packet(12, 0, Buffer.alloc(0)));
        const event = await this._next((item) => item.type === "close" || item.type === 13);
        gate(event.type === 13, "pingresp");
        return true;
    }

    async close() {
        if (!this.socket) return;
        if (!this.closed && this.socket.writable) {
            this.socket.write(encodeDisconnect());
            this.socket.end();
            await Promise.race([
                new Promise((resolve) => this.socket.once("close", resolve)),
                sleep(100).then(() => this.socket.destroy()),
            ]);
        }
        this.socket.destroy();
    }
}

function reasonClass(reason) {
    if (publishAckSucceeded(reason)) return "success";
    if (reason === "closed") return "connection_closed";
    if (reason === 0x86) return "bad_username_or_password";
    if (reason === 0x87) return "not_authorized";
    if (typeof reason === "number" && reason >= 0x80) return "negative_reason";
    return "unexpected_reason";
}

function validateManifestIdentity(manifest) {
    gate(manifest?.schema === MANIFEST_SCHEMA && manifest.manifest_version === 1 && manifest.pass === "B1A", "manifest_identity");
    gate(manifest.classification === "ci-only-same-repository-non-authoritative-composite-policy-foundation" && manifest.authoritative === false, "manifest_classification");
    gate(manifest.scope?.base_topic === "zigbee2mqtt", "manifest_scope");
    gate(manifest.preflight_acl?.schema === "true-family-physical-probe-acl-plan-v2" && manifest.preflight_acl?.effective_policy?.schema === "true-family-physical-probe-acl-plan-v2", "manifest_preflight_acl");
    gate(manifest.preflight_acl?.policy_digest === manifest.scope?.preflight_acl_digest, "manifest_preflight_acl");
    gate(manifest.artifact?.sha256 === "1d40f5a0d8b01ad7e7eb6c92b52319285f76bdbff8abbff0b6743046258645c1", "manifest_artifact");
    exactKeys(manifest.timing, [
        "private_file_poll_milliseconds", "quick_record_wait_seconds", "quick_record_wait_attempts",
        "source_ready_wait_seconds", "source_ready_wait_attempts", "client_exit_inspect_interval_milliseconds",
        "client_before_container_timeout_seconds", "client_before_timeout_reserve_seconds",
        "client_failure_log_tail_lines", "client_failure_log_capture_timeout_seconds",
    ], "manifest_timing_shape");
    gate(
        manifest.timing.private_file_poll_milliseconds === 500
        && manifest.timing.quick_record_wait_seconds === 10
        && manifest.timing.quick_record_wait_attempts === 20
        && manifest.timing.source_ready_wait_seconds === 180
        && manifest.timing.source_ready_wait_attempts === 360
        && manifest.timing.client_exit_inspect_interval_milliseconds === 500
        && manifest.timing.client_before_container_timeout_seconds === 240
        && manifest.timing.client_before_timeout_reserve_seconds === 60
        && manifest.timing.client_failure_log_tail_lines === 1
        && manifest.timing.client_failure_log_capture_timeout_seconds === 30,
        "manifest_timing",
    );
    gate(
        manifest.timing.source_ready_wait_attempts * manifest.timing.private_file_poll_milliseconds === manifest.timing.source_ready_wait_seconds * 1000
        && manifest.timing.client_before_container_timeout_seconds - manifest.timing.source_ready_wait_seconds === manifest.timing.client_before_timeout_reserve_seconds
        && manifest.timing.client_before_timeout_reserve_seconds >= 30,
        "manifest_timing_reserve",
    );
}

function validatePrincipalCredential(item, expected) {
    exactKeys(item, ["username", "client_id", "password"], "credential_shape");
    gate(item.username === expected.username && item.client_id === expected.client_id && PASSWORD_PATTERN.test(item.password), "credential_identity");
    return item;
}

function validateAdminCredential(credentials, manifest) {
    exactKeys(credentials, ["schema", "principal"], "admin_credential_shape");
    gate(credentials.schema === "true-family-pass-b1a-admin-credential-v1", "admin_credential_schema");
    return validatePrincipalCredential(credentials.principal, manifest.principals.admin);
}

function validateFrontendCredentials(credentials, manifest) {
    exactKeys(credentials, ["schema", "principals", "wrong_password"], "frontend_credential_shape");
    gate(credentials.schema === "true-family-pass-b1a-frontend-credentials-v1" && PASSWORD_PATTERN.test(credentials.wrong_password), "frontend_credential_schema");
    exactKeys(credentials.principals, FRONTEND_PRINCIPALS, "frontend_credential_principals");
    const passwords = new Set([credentials.wrong_password]);
    for (const key of FRONTEND_PRINCIPALS) {
        const item = validatePrincipalCredential(credentials.principals[key], manifest.principals[key]);
        gate(!passwords.has(item.password), "credential_uniqueness");
        passwords.add(item.password);
    }
    return credentials;
}

function validateObserverCredential(credentials, manifest) {
    exactKeys(credentials, ["schema", "principal"], "observer_credential_shape");
    gate(credentials.schema === "true-family-pass-b1a-observer-credential-v1", "observer_credential_schema");
    return validatePrincipalCredential(credentials.principal, manifest.principals.observer);
}

function generatePrincipalCredential(expected) {
    return {username: expected.username, client_id: expected.client_id, password: crypto.randomBytes(32).toString("base64url")};
}

function normalizeAssignment(item, name) {
    exactKeys(item, [name, ...(Object.hasOwn(item, "priority") ? ["priority"] : [])], "readback_assignment_shape");
    return {[name]: item[name], priority: item.priority ?? -1};
}

function normalizeClient(item) {
    const allowed = new Set(["username", "clientid", "disabled", "roles", "groups", "textname", "textdescription"]);
    gate(item && typeof item === "object" && !Array.isArray(item) && Object.keys(item).every((key) => allowed.has(key)), "readback_client_shape");
    gate(typeof item.username === "string" && typeof item.clientid === "string", "readback_client_identity");
    gate(item.disabled === undefined || typeof item.disabled === "boolean", "readback_client_disabled");
    gate(Array.isArray(item.roles) && Array.isArray(item.groups), "readback_client_assignments");
    return {
        username: item.username,
        clientid: item.clientid,
        disabled: item.disabled ?? false,
        roles: item.roles.map((role) => normalizeAssignment(role, "rolename")),
        groups: item.groups.map((group) => normalizeAssignment(group, "groupname")),
    };
}

function normalizeAcl(item) {
    exactKeys(item, ["acltype", "topic", "priority", "allow"], "readback_acl_shape");
    gate(typeof item.acltype === "string" && typeof item.topic === "string" && Number.isInteger(item.priority) && typeof item.allow === "boolean", "readback_acl_value");
    return {acltype: item.acltype, topic: item.topic, priority: item.priority, allow: item.allow};
}

function normalizeRole(item) {
    const allowed = new Set(["rolename", "acls", "textname", "textdescription"]);
    gate(item && typeof item === "object" && !Array.isArray(item) && Object.keys(item).every((key) => allowed.has(key)), "readback_role_shape");
    gate(typeof item.rolename === "string" && Array.isArray(item.acls), "readback_role_value");
    const acls = item.acls.map(normalizeAcl);
    return {rolename: item.rolename, acls};
}

function normalizeGroup(item) {
    const allowed = new Set(["groupname", "roles", "clients", "textname", "textdescription"]);
    gate(item && typeof item === "object" && !Array.isArray(item) && Object.keys(item).every((key) => allowed.has(key)), "readback_group_shape");
    gate(typeof item.groupname === "string" && Array.isArray(item.roles) && Array.isArray(item.clients), "readback_group_value");
    return {
        groupname: item.groupname,
        roles: item.roles.map((role) => normalizeAssignment(role, "rolename")),
        clients: item.clients.map((client) => {
            gate(client && typeof client === "object" && typeof client.username === "string", "readback_group_client");
            return {username: client.username};
        }),
    };
}

export function normalizeReadback(raw) {
    exactKeys(raw, ["defaults", "anonymous_group", "clients", "roles", "groups"], "readback_shape");
    gate(Array.isArray(raw.defaults) && typeof raw.anonymous_group === "string", "readback_defaults_shape");
    const defaults = raw.defaults.map((item) => {
        exactKeys(item, ["acltype", "allow"], "readback_default_shape");
        gate(typeof item.acltype === "string" && typeof item.allow === "boolean", "readback_default_value");
        return {acltype: item.acltype, allow: item.allow};
    });
    gate(Array.isArray(raw.clients) && Array.isArray(raw.roles) && Array.isArray(raw.groups), "readback_lists");
    return {
        defaults,
        anonymous_group: raw.anonymous_group,
        clients: raw.clients.map(normalizeClient),
        roles: raw.roles.map(normalizeRole),
        groups: raw.groups.map(normalizeGroup),
    };
}

export function validateReadback(raw, expected) {
    const normalized = normalizeReadback(raw);
    const normalizedExpected = normalizeReadback(expected);
    gate(same(normalized, normalizedExpected), "readback_mismatch");
    return normalized;
}

export function expectedReadbackFromManifest(manifest) {
    const policy = manifest.policy;
    const clients = [
        {
            username: manifest.principals.admin.username,
            clientid: manifest.principals.admin.client_id,
            disabled: false,
            roles: [{rolename: policy.admin_role.rolename, priority: -1}],
            groups: [],
        },
        ...policy.clients.map((client) => ({
            username: manifest.principals[client.principal].username,
            clientid: manifest.principals[client.principal].client_id,
            disabled: false,
            roles: client.roles,
            groups: [],
        })),
    ].sort((left, right) => compareStrings(left.username, right.username));
    return normalizeReadback({
        defaults: policy.defaults,
        anonymous_group: "",
        clients,
        roles: [policy.admin_role, ...policy.roles].sort((left, right) => compareStrings(left.rolename, right.rolename)),
        groups: [],
    });
}

export function buildSourceInventory(sourceBytes, artifactName = "true_family_brt_probe.mjs") {
    gate(Buffer.isBuffer(sourceBytes) && sourceBytes.length === 164_691, "source_size");
    const source = sourceBytes.toString("utf8");
    gate(Buffer.from(source, "utf8").equals(sourceBytes), "source_utf8");
    return Buffer.from(JSON.stringify([{name: artifactName, code: source}]), "utf8");
}

function principalOptions(context, key, overrides = {}) {
    const principal = context.credentials.principals[key];
    gate(principal, "principal_key");
    return {
        host: context.host,
        port: context.port,
        clientId: overrides.clientId ?? principal.client_id,
        username: overrides.username ?? principal.username,
        password: overrides.password ?? principal.password,
        cleanStart: overrides.cleanStart ?? true,
        sessionExpiry: overrides.sessionExpiry ?? 0,
    };
}

async function openPrincipal(context, key, overrides = {}) {
    const client = new MqttClient(principalOptions(context, key, overrides));
    const connack = await client.open();
    gate(connack.reason === 0, "principal_connect");
    client.connack = connack;
    return client;
}

async function connectClass(options) {
    const client = new MqttClient(options);
    const connack = await client.open();
    await client.close();
    return {reason: reasonClass(connack.reason), packetTypes: client.connectionPacketTypes};
}

async function createControl(context) {
    let client;
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
        try {
            client = await openPrincipal(context, "admin");
            break;
        } catch {
            blockingDelay(250);
        }
    }
    gate(client, "control_connect");
    const suback = await client.subscribe([CONTROL_RESPONSE_TOPIC]);
    gate(same(suback.reasons, [1]) || same(suback.reasons, [0]), "control_subscribe");
    return {client, correlations: new Set()};
}

async function controlCommand(control, command) {
    const correlationData = `b1a-${crypto.randomBytes(16).toString("hex")}`;
    gate(/^b1a-[0-9a-f]{32}$/u.test(correlationData), "control_correlation_shape");
    gate(!control.correlations.has(correlationData), "control_correlation_unique");
    control.correlations.add(correlationData);
    const complete = {...command, correlationData};
    const publish = await control.client.publish(CONTROL_REQUEST_TOPIC, Buffer.from(canonical({commands: [complete]}), "utf8"), {qos: 1, retain: false});
    gate(publishResultSucceeded(publish), "control_puback");
    const responseMessage = await control.client.message(CONTROL_RESPONSE_TOPIC);
    let response;
    try {
        response = JSON.parse(responseMessage.payload.toString("utf8"));
    } catch {
        throw new B1AFailure("control_response_json");
    }
    exactKeys(response, ["responses"], "control_response_shape");
    gate(Array.isArray(response.responses) && response.responses.length === 1, "control_response_count");
    const item = response.responses[0];
    gate(item && typeof item === "object" && item.command === command.command && item.correlationData === correlationData, "control_response_identity");
    gate(!Object.hasOwn(item, "error"), "control_response_error");
    return item.data;
}

async function installPolicy(context, control, generated) {
    const policy = context.manifest.policy;
    await controlCommand(control, {
        command: "modifyRole",
        rolename: policy.admin_role.rolename,
        acls: policy.admin_role.acls,
    });
    await controlCommand(control, {command: "setDefaultACLAccess", acls: policy.defaults});
    for (const role of policy.roles) {
        await controlCommand(control, {command: "createRole", rolename: role.rolename, acls: role.acls});
    }
    for (const client of policy.clients) {
        const credential = generated.principals[client.principal];
        await controlCommand(control, {
            command: "createClient",
            username: credential.username,
            password: credential.password,
            clientid: credential.client_id,
            roles: client.roles,
        });
    }
    await createObserver(context, control, generated.observer);
}

async function createObserver(context, control, observer) {
    const observerRole = context.manifest.policy.observer_role;
    await controlCommand(control, {command: "createRole", rolename: observerRole.rolename, acls: observerRole.acls});
    await controlCommand(control, {
        command: "createClient",
        username: observer.username,
        password: observer.password,
        clientid: observer.client_id,
        roles: [{rolename: observerRole.rolename, priority: 100}],
    });
}

async function deleteObserver(context, control) {
    await controlCommand(control, {command: "deleteClient", username: context.manifest.principals.observer.username});
    await controlCommand(control, {command: "deleteRole", rolename: context.manifest.policy.observer_role.rolename});
}

async function readback(control, expected) {
    const defaults = await controlCommand(control, {command: "getDefaultACLAccess"});
    const anonymous = await controlCommand(control, {command: "getAnonymousGroup"});
    const clients = await controlCommand(control, {command: "listClients", verbose: true, count: -1, offset: 0});
    const roles = await controlCommand(control, {command: "listRoles", verbose: true, count: -1, offset: 0});
    const groups = await controlCommand(control, {command: "listGroups", verbose: true, count: -1, offset: 0});
    gate(clients.totalCount === clients.clients.length && roles.totalCount === roles.roles.length && groups.totalCount === groups.groups.length, "readback_total_count");
    for (const item of clients.clients) {
        const detail = await controlCommand(control, {command: "getClient", username: item.username});
        gate(same(normalizeClient(detail.client), normalizeClient(item)), "readback_client_detail");
    }
    for (const item of roles.roles) {
        const detail = await controlCommand(control, {command: "getRole", rolename: item.rolename});
        gate(same(normalizeRole(detail.role), normalizeRole(item)), "readback_role_detail");
    }
    for (const item of groups.groups) {
        const detail = await controlCommand(control, {command: "getGroup", groupname: item.groupname});
        gate(same(normalizeGroup(detail.group), normalizeGroup(item)), "readback_group_detail");
    }
    const normalized = validateReadback({
        defaults: defaults.acls,
        anonymous_group: anonymous.group.groupname,
        clients: clients.clients,
        roles: roles.roles,
        groups: groups.groups,
    }, expected);
    return {normalized, digest: sha256Bytes(Buffer.from(canonical(normalized), "utf8"))};
}

async function authenticationMatrix(context) {
    for (const key of FRONTEND_PRINCIPALS) {
        const client = await openPrincipal(context, key);
        try {
            await client.ping();
        } finally {
            await client.close();
        }
    }
    const wrongPassword = await connectClass(principalOptions(context, "orchestrator", {password: context.credentials.wrong_password}));
    gate(["bad_username_or_password", "not_authorized"].includes(wrongPassword.reason) && same(wrongPassword.packetTypes, [2]), "auth_wrong_password_broker");
    const wrongClientId = await connectClass(principalOptions(context, "orchestrator", {clientId: context.manifest.authentication.wrong_client_id}));
    const anonymous = await connectClass({host: context.host, port: context.port, clientId: context.manifest.authentication.anonymous_client_id, cleanStart: true, sessionExpiry: 0});
    const unknown = await connectClass({
        host: context.host,
        port: context.port,
        clientId: context.manifest.authentication.unknown_client_id,
        username: context.manifest.authentication.unknown_username,
        password: context.credentials.wrong_password,
        cleanStart: true,
        sessionExpiry: 0,
    });
    const admin = await connectClass({
        host: context.host,
        port: context.port,
        clientId: context.manifest.principals.admin.client_id,
        username: context.manifest.principals.admin.username,
        password: context.credentials.wrong_password,
        cleanStart: true,
        sessionExpiry: 0,
    });
    const observer = await connectClass({
        host: context.host,
        port: context.port,
        clientId: context.manifest.principals.observer.client_id,
        username: context.manifest.principals.observer.username,
        password: context.credentials.wrong_password,
        cleanStart: true,
        sessionExpiry: 0,
    });
    for (const value of [wrongClientId, anonymous, unknown, admin, observer]) {
        gate(value.reason === "connection_closed" && value.packetTypes.length === 0, "auth_gateway_denial");
    }
    return {
        correct_frontend_bindings: true,
        ping_round_trip: true,
        wrong_password_broker_reason: wrongPassword.reason,
        wrong_client_id_gateway_close: true,
        anonymous_gateway_close: true,
        unknown_gateway_close: true,
        admin_frontend_gateway_close: true,
        observer_frontend_gateway_close: true,
        gateway_denials_without_ack_or_publish: true,
    };
}

function matrixPublisherPrincipal(context, topic) {
    return context.manifest.topics.request_topics.includes(topic) ? "orchestrator" : "z2m";
}

function matrixTopic(value, fixture, baseTopic) {
    if (fixture === undefined) return value;
    if (fixture === "maximum") return `${baseTopic}/${"a".repeat(244)}`;
    if (fixture === "overlength") return `${baseTopic}/${"a".repeat(245)}`;
    if (fixture === "empty") return "";
    if (fixture === "leading_slash") return `/${baseTopic}/invalid`;
    if (fixture === "trailing_slash") return `${baseTopic}/invalid/`;
    if (fixture === "boundary_space") return ` ${baseTopic}/invalid`;
    if (fixture === "boundary_unicode") return `\u00a0${baseTopic}/invalid`;
    if (fixture === "control") return `${baseTopic}/\u0001invalid`;
    if (fixture === "c1_delete") return `${baseTopic}/\u007finvalid`;
    if (fixture === "c1_first") return `${baseTopic}/\u0080invalid`;
    if (fixture === "c1_last") return `${baseTopic}/\u009finvalid`;
    if (fixture === "noncharacter_fdd0") return `${baseTopic}/\ufdd0invalid`;
    if (fixture === "noncharacter_fdef") return `${baseTopic}/\ufdefinvalid`;
    if (fixture === "noncharacter_fffe") return `${baseTopic}/\ufffeinvalid`;
    if (fixture === "noncharacter_ffff") return `${baseTopic}/\uffffinvalid`;
    if (fixture === "noncharacter_plane_end") return `${baseTopic}/${String.fromCodePoint(0x10ffff)}invalid`;
    if (fixture === "surrogate_utf8") return `${baseTopic}/invalid`;
    if (fixture === "wildcard_plus") return `${baseTopic}/+`;
    if (fixture === "wildcard_hash") return `${baseTopic}/#`;
    if (fixture === "malformed_utf8") return `${baseTopic}/invalid`;
    const depth = /^bridge_request_depth_(0|8|32|100)$/u.exec(fixture);
    if (depth) {
        const count = Number(depth[1]);
        const prefix = count === 0 ? "" : `${Array.from({length: count}, () => "a").join("/")}/`;
        return `${baseTopic}/${prefix}bridge/request/action`;
    }
    throw new B1AFailure("matrix_topic_fixture");
}

async function publishMatrix(context) {
    let allowed = 0;
    let denied = 0;
    let positiveDeliveries = 0;
    const deepDepths = new Set();
    const proofs = new Set();
    for (const [index, item] of context.manifest.matrix.publish.entries()) {
        const topic = matrixTopic(item.topic, item.topic_fixture, context.manifest.scope.base_topic);
        const qos = item.qos ?? 1;
        const retain = item.retain ?? false;
        const id = item.id ?? `case-${index}`;
        const encoding = item.encoding ?? (["malformed_utf8", "surrogate_utf8"].includes(item.topic_fixture) ? item.topic_fixture : topicContractValid(topic) ? "normal" : "unchecked");
        let proof = item.proof;
        if (!proof && item.allowed) proof = "positive";
        if (!proof && item.principal === "z2m" && containsBridgeRequest(topic)) proof = "deep_containment";
        if (!proof && item.principal === "orchestrator" && context.manifest.topics.request_topics.includes(topic) && qos !== 1) proof = "qos";
        if (!proof && item.principal === "orchestrator" && context.manifest.topics.request_topics.includes(topic) && retain !== false) proof = "retain";
        if (!proof && (!topicContractValid(topic) || ["malformed_utf8", "surrogate_utf8"].includes(item.topic_fixture))) proof = "topic_validity";
        if (!proof) proof = "principal";
        const oracleAllowed = ["malformed_utf8", "surrogate_utf8"].includes(item.topic_fixture)
            ? false
            : gatewayAllowsPublish(context.manifest, item.principal, {topic, qos, retain});
        gate(oracleAllowed === item.allowed, "publish_matrix_oracle_equivalence");
        const publisher = await openPrincipal(context, item.principal);
        let subscriber;
        try {
            if (item.allowed) {
                if (item.principal === "z2m") {
                    subscriber = publisher;
                    const suback = await subscriber.subscribe([{filter: topic, qos}]);
                    gate(suback.reasons[0] <= qos, "publish_positive_subscribe");
                } else {
                    subscriber = await openPrincipal(context, "z2m");
                    const suback = await subscriber.subscribe([{filter: topic, qos}]);
                    gate(suback.reasons[0] <= qos, "publish_positive_subscribe");
                }
                const payload = Buffer.from(`b1a-publish-${id}`, "utf8");
                const ack = await publisher.publish(topic, payload, {qos, retain});
                gate(publishResultSucceeded(ack), "publish_expected_allow");
                const message = await subscriber.message(topic);
                gate(message.payload.equals(payload), "publish_positive_delivery");
                if (retain) {
                    const cleared = await publisher.publish(topic, Buffer.alloc(0), {qos: Math.max(1, qos), retain: true});
                    gate(publishResultSucceeded(cleared), "publish_positive_retained_clear");
                }
                allowed += 1;
                positiveDeliveries += 1;
            } else {
                const packetId = publisher.nextPacketId();
                const frame = encoding === "malformed_utf8" || encoding === "surrogate_utf8"
                    ? encodeRawTopicPublish(encoding === "malformed_utf8" ? Buffer.from([0xff]) : Buffer.from([0xed, 0xa0, 0x80]), Buffer.from("b1a-denied", "utf8"), {qos, retain, packetId})
                    : encoding === "unchecked"
                        ? encodeUncheckedPublish(topic, Buffer.from("b1a-denied", "utf8"), {qos, retain, packetId})
                        : encodePublish(topic, Buffer.from("b1a-denied", "utf8"), {qos, retain, packetId});
                await publisher.sendAndExpectClose(frame);
                denied += 1;
            }
            proofs.add(proof);
            if (proof === "deep_containment") {
                const levels = topic.split("/");
                deepDepths.add(levels.findIndex((level, levelIndex) => level === "bridge" && levels[levelIndex + 1] === "request") - 1);
            }
        } finally {
            if (subscriber && subscriber !== publisher) await subscriber.close();
            await publisher.close();
        }
    }
    gate(allowed > 0 && denied > 0 && positiveDeliveries === allowed, "publish_matrix_controls");
    for (const depth of [0, 8, 32, 100]) gate(deepDepths.has(depth), "publish_deep_containment");
    for (const proof of ["deep_containment", "qos", "retain", "topic_validity", "principal", "positive"]) gate(proofs.has(proof), "publish_matrix_proof");
    return {
        cases: allowed + denied,
        allowed,
        denied,
        gateway_close_denials: denied,
        broker_positive_deliveries: positiveDeliveries,
        deep_containment_depths: [0, 8, 32, 100],
        qos_enforced: true,
        retain_enforced: true,
        topic_contract_enforced: true,
        pure_oracle_equivalent: true,
    };
}

async function subscribeMatrix(context) {
    let allowed = 0;
    let denied = 0;
    let positiveDeliveries = 0;
    const proofs = new Set();
    for (const [index, item] of context.manifest.matrix.subscribe.entries()) {
        const filter = matrixTopic(item.filter, item.filter_fixture, context.manifest.scope.base_topic);
        const deliveryTopic = item.filter_fixture === "maximum" ? filter : item.delivery_topic;
        const qos = item.qos ?? 1;
        const id = item.id ?? `case-${index}`;
        let proof = item.proof;
        if (!proof && item.allowed) proof = "positive";
        if (!proof && filter.startsWith("$share/")) proof = "shared";
        if (!proof && (filter.includes("+") || filter.includes("#"))) proof = "wildcard";
        if (!proof && (!mqttFilterStructurallyValid(filter) || ["malformed_utf8", "surrogate_utf8"].includes(item.filter_fixture))) proof = "topic_validity";
        if (!proof && filter === context.manifest.topics.source) proof = "source_privacy";
        if (!proof && [context.manifest.topics.candidate_friendly, context.manifest.topics.candidate_friendly_set, context.manifest.topics.candidate_ieee, context.manifest.topics.candidate_ieee_descendant].includes(filter)) proof = "candidate_privacy";
        if (!proof) proof = "principal";
        const oracleAllowed = ["malformed_utf8", "surrogate_utf8"].includes(item.filter_fixture)
            ? false
            : gatewayAllowsSubscribe(context.manifest, item.principal, filter);
        gate(oracleAllowed === item.allowed, "subscribe_matrix_oracle_equivalence");
        const subscriber = await openPrincipal(context, item.principal);
        let publisher;
        try {
            if (item.allowed) {
                const suback = await subscriber.subscribe([{filter, qos}]);
                gate(suback.reasons[0] <= qos, "subscribe_expected_allow");
                const publisherPrincipal = matrixPublisherPrincipal(context, deliveryTopic);
                publisher = item.principal === publisherPrincipal ? subscriber : await openPrincipal(context, publisherPrincipal);
                const payload = Buffer.from(`b1a-subscribe-${id}`, "utf8");
                const ack = await publisher.publish(deliveryTopic, payload, {qos: 1, retain: false});
                gate(publishResultSucceeded(ack), "subscribe_control_publish");
                const message = await subscriber.message(deliveryTopic);
                gate(message.payload.equals(payload), "subscribe_control_delivery");
                allowed += 1;
                positiveDeliveries += 1;
            } else {
                const packetId = subscriber.nextPacketId();
                const frame = ["malformed_utf8", "surrogate_utf8", "empty"].includes(item.filter_fixture)
                    ? encodeRawFilterSubscribe(packetId, item.filter_fixture === "empty" ? Buffer.alloc(0) : item.filter_fixture === "malformed_utf8" ? Buffer.from([0xff]) : Buffer.from([0xed, 0xa0, 0x80]))
                    : encodeSubscribe(packetId, [{filter, qos}]);
                await subscriber.sendAndExpectClose(frame);
                denied += 1;
            }
            proofs.add(proof);
        } finally {
            if (publisher && publisher !== subscriber) await publisher.close();
            await subscriber.close();
        }
    }
    gate(allowed > 0 && denied > 0 && positiveDeliveries === allowed, "subscribe_matrix_controls");
    for (const proof of ["wildcard", "shared", "topic_validity", "source_privacy", "candidate_privacy", "principal", "positive"]) gate(proofs.has(proof), "subscribe_matrix_proof");
    return {
        cases: allowed + denied,
        allowed,
        denied,
        gateway_close_denials: denied,
        broker_positive_deliveries: positiveDeliveries,
        wildcard_enforced: true,
        shared_enforced: true,
        concrete_subscription_policy_enforced: true,
        pure_oracle_equivalent: true,
    };
}

async function proveRequestTopicsNotRetained(context) {
    for (const topic of context.manifest.topics.request_topics) {
        const z2m = await openPrincipal(context, "z2m");
        try {
            const suback = await z2m.subscribe([topic]);
            gate(suback.reasons[0] <= 2, "request_retained_subscribe");
            await z2m.noMessage(topic, 350);
            const orchestrator = await openPrincipal(context, "orchestrator");
            try {
                const payload = Buffer.from("b1a-request-positive-control", "utf8");
                const ack = await orchestrator.publish(topic, payload, {qos: 1, retain: false});
                gate(publishResultSucceeded(ack), "request_positive_puback");
                const delivered = await z2m.message(topic);
                gate(delivered.payload.equals(payload) && delivered.retain === false, "request_positive_delivery");
            } finally {
                await orchestrator.close();
            }
        } finally {
            await z2m.close();
        }
    }
    return true;
}

async function waitForPrivateRecord(file, schema, milliseconds = 10_000) {
    const deadline = Date.now() + milliseconds;
    while (Date.now() < deadline) {
        if (fs.existsSync(file)) {
            const value = readPrivateJson(file, "coord_json");
            gate(value.schema === schema && value.result === "pass", "coord_record");
            return value;
        }
        blockingDelay(50);
    }
    throw new B1AFailure("coord_timeout");
}

async function proveFrontendIsolation() {
    let dnsBlocked = false;
    try {
        await dns.lookup("broker");
    } catch (error) {
        dnsBlocked = ["ENOTFOUND", "EAI_AGAIN"].includes(error?.code);
    }
    const tcpBlocked = dnsBlocked || await tcpUnreachable("broker", 18883);
    gate(dnsBlocked && tcpBlocked, "frontend_broker_isolation");
    let hostAliasServiceUnreachable = true;
    for (const alias of ["host.docker.internal", "gateway.docker.internal", "_gateway"]) {
        try {
            await dns.lookup(alias);
            hostAliasServiceUnreachable &&= await tcpUnreachable(alias, 2375);
            hostAliasServiceUnreachable &&= await tcpUnreachable(alias, 2376);
        } catch (error) {
            gate(["ENOTFOUND", "EAI_AGAIN"].includes(error?.code), "frontend_host_alias_probe");
        }
    }
    const routeLines = fs.readFileSync("/proc/net/route", "utf8").trim().split("\n").slice(1);
    const defaultRouteObserved = routeLines.some((line) => line.trim().split(/\s+/u)[1] === "00000000");
    const externalTcpUnreachable = await tcpUnreachable("1.1.1.1", 443);
    gate(hostAliasServiceUnreachable && externalTcpUnreachable, "frontend_external_probe");
    return {
        broker_dns_unresolvable: true,
        broker_tcp_unreachable: true,
        gateway_only_broker_path: true,
        default_route_observed: defaultRouteObserved,
        host_aliases_probed: true,
        host_alias_docker_api_ports_unreachable: true,
        external_tcp_unreachable: true,
        same_runner_host_isolation_proven: false,
    };
}

async function tcpUnreachable(host, port) {
    return new Promise((resolve) => {
        const socket = net.createConnection({host, port});
        const timer = setTimeout(() => {
            socket.destroy();
            resolve(true);
        }, 500);
        timer.unref();
        socket.once("connect", () => {
            clearTimeout(timer);
            socket.destroy();
            resolve(false);
        });
        socket.once("error", () => {
            clearTimeout(timer);
            resolve(true);
        });
    });
}

async function sourcePrivacyFrontend(context) {
    const sourceTopic = context.manifest.topics.source;
    const payload = buildSourceInventory(context.sourceBytes, context.manifest.artifact.filename);
    const z2m = await openPrincipal(context, "z2m");
    try {
        gate(publishResultSucceeded(await z2m.publish(sourceTopic, payload, {qos: 1, retain: true})), "source_publish");
    } finally {
        await z2m.close();
    }
    let privacyCases = 0;
    for (const principal of context.manifest.source_privacy.principals) {
        for (const filter of context.manifest.source_privacy.denied_filters) {
            const subscriber = await openPrincipal(context, principal, {sessionExpiry: 60});
            try {
                await subscriber.sendAndExpectClose(encodeSubscribe(subscriber.nextPacketId(), [{filter, qos: 1}]));
            } finally {
                await subscriber.close();
            }
            const reconnect = await openPrincipal(context, principal, {cleanStart: false, sessionExpiry: 60});
            try {
                gate(reconnect.connack.sessionPresent === true, "source_privacy_session_resume");
                await reconnect.sendAndExpectClose(encodeSubscribe(reconnect.nextPacketId(), [{filter, qos: 1}]));
            } finally {
                await reconnect.close();
            }
            privacyCases += 1;
        }
    }
    writePrivateJson(`${context.coordDir}/source-ready.json`, {schema: "true-family-pass-b1a-source-ready-v1", result: "pass"});
    await waitForPrivateRecord(`${context.coordDir}/observer-before.json`, "true-family-pass-b1a-observer-before-coord-v1");
    const clear = await openPrincipal(context, "z2m");
    try {
        gate(publishResultSucceeded(await clear.publish(sourceTopic, Buffer.alloc(0), {qos: 1, retain: true})), "source_clear");
    } finally {
        await clear.close();
    }
    return {
        synthetic_source: true,
        real_externaljs_source_path: false,
        retained_payload_sha256: sha256Bytes(payload),
        source_sha256: sha256Bytes(context.sourceBytes),
        source_acl_privacy_cases: privacyCases,
        fresh_gateway_close_proven: true,
        reconnect_gateway_close_proven: true,
        wildcard_and_shared_gateway_close_proven: true,
        retained_source_cleared_by_z2m: true,
        raw_source_emitted: false,
    };
}

async function runObserverBefore(context) {
    const topic = context.manifest.topics.source;
    const payload = buildSourceInventory(context.sourceBytes, context.manifest.artifact.filename);
    const observer = await openPrincipal(context, "observer");
    try {
        gate((await observer.subscribe([topic])).reasons[0] <= 1, "source_observer_subscribe");
        const replay = await observer.message(topic);
        gate(replay.retain === true && replay.qos === 1 && replay.payload.equals(payload), "source_observer_replay");
        const inventory = JSON.parse(replay.payload.toString("utf8"));
        gate(Array.isArray(inventory) && inventory.length === 1 && inventory[0].name === context.manifest.artifact.filename, "source_inventory_shape");
        gate(Buffer.byteLength(inventory[0].code, "utf8") === context.manifest.artifact.byte_length, "source_inventory_size");
        gate(sha256Bytes(Buffer.from(inventory[0].code, "utf8")) === context.manifest.artifact.sha256, "source_inventory_digest");
    } finally {
        await observer.close();
    }
    writePrivateJson(`${context.coordDir}/observer-before.json`, {schema: "true-family-pass-b1a-observer-before-coord-v1", result: "pass"});
    return {
        schema: RUNTIME_SCHEMA,
        result: "pass",
        phase: "observer_before",
        security: processSecurity(),
        retained_replay_qos1: true,
        payload_sha256: sha256Bytes(payload),
        source_sha256: context.manifest.artifact.sha256,
        backend_only: true,
    };
}

async function runObserverAfter(context) {
    const topic = context.manifest.topics.source;
    const observer = await openPrincipal(context, "observer");
    const marker = Buffer.from("b1a-post-restart-source-control", "utf8");
    try {
        gate((await observer.subscribe([topic])).reasons[0] <= 1, "restart_observer_subscribe");
        await observer.noMessage(topic, 500);
        writePrivateJson(`${context.coordDir}/observer-after-ready.json`, {schema: "true-family-pass-b1a-observer-after-ready-v1", result: "pass"});
        const delivered = await observer.message(topic, 10_000);
        gate(delivered.payload.equals(marker) && delivered.retain === false, "restart_source_control_delivery");
    } finally {
        await observer.close();
    }
    return {
        schema: RUNTIME_SCHEMA,
        result: "pass",
        phase: "observer_after",
        security: processSecurity(),
        old_retained_replay_absent: true,
        positive_nonretained_delivery: true,
        backend_only: true,
    };
}

function processSecurity() {
    const status = Object.fromEntries(fs.readFileSync("/proc/self/status", "utf8").split("\n").filter((line) => line.includes(":")).map((line) => {
        const index = line.indexOf(":");
        return [line.slice(0, index), line.slice(index + 1).trim()];
    }));
    const uid = Number.parseInt(status.Uid?.split(/\s+/u)[0] ?? "0", 10);
    const capabilitiesZero = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"].every((key) => /^0+$/u.test(status[key] ?? ""));
    const forbidden = [
        "/homeassistant",
        "/addons",
        "/addon_configs",
        "/github/workspace",
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/dev/ttyUSB0",
        "/dev/ttyACM0",
        "/dev/serial",
    ].every((entry) => !fs.existsSync(entry));
    let rootReadOnly = false;
    try {
        fs.writeFileSync("/.b1a-write-test", "blocked", {flag: "wx"});
        fs.unlinkSync("/.b1a-write-test");
    } catch (error) {
        rootReadOnly = ["EACCES", "EPERM", "EROFS"].includes(error?.code);
    }
    const interfaces = Object.keys(os.networkInterfaces());
    const result = {
        uid_nonzero: Number.isSafeInteger(uid) && uid > 0,
        no_new_privs: status.NoNewPrivs === "1",
        capability_sets_zero: capabilitiesZero,
        seccomp_filtering: status.Seccomp === "2",
        read_only_root: rootReadOnly,
        forbidden_host_paths_unavailable: forbidden,
        private_network_interface_only: interfaces.every((name) => name === "lo" || name === "eth0"),
    };
    gate(Object.values(result).every(Boolean), "container_security");
    return result;
}

function runtimeContext() {
    const allowedEnvironment = new Set([
        "PATH", "NODE_VERSION", "B1A_MODE", "B1A_ENDPOINT_HOST", "B1A_ENDPOINT_PORT",
        "B1A_LISTEN_HOST", "B1A_LISTEN_PORT", "B1A_STATUS_PATH", "B1A_COORD_DIR", "B1A_OUTPUT_DIR", "TMPDIR",
    ]);
    gate(Object.keys(process.env).every((key) => allowedEnvironment.has(key)), "runtime_environment");
    gate(process.env.NODE_VERSION === "20.19.2" && process.env.PATH === "/usr/local/bin:/usr/bin:/bin" && process.env.TMPDIR === "/tmp", "runtime_environment");
    const mode = process.env.B1A_MODE;
    gate([
        "gateway", "install", "client_before", "observer_before", "readback_before",
        "backend_before", "readback_after", "backend_after", "observer_after",
        "client_after", "readiness_after", "readiness_final", "client_final", "backend_final", "readback_final",
    ].includes(mode), "runtime_mode");
    const host = process.env.B1A_ENDPOINT_HOST;
    const port = Number(process.env.B1A_ENDPOINT_PORT);
    gate((mode === "gateway" || mode.startsWith("readback") || mode.startsWith("readiness") || mode === "install" || mode.startsWith("observer") || mode.startsWith("backend"))
        ? host === "broker" && port === 18883
        : host === "gateway" && port === 18884, "runtime_endpoint");
    const manifest = readJson("/input/manifest.json", "manifest_json");
    validateManifestIdentity(manifest);
    gate(gatewayPolicyDigest(manifest) === manifest.gateway.policy_sha256, "runtime_gateway_policy");
    return {
        mode,
        host,
        port,
        manifest,
        coordDir: process.env.B1A_COORD_DIR,
        outputDir: process.env.B1A_OUTPUT_DIR,
    };
}

function loadAdminContext(context) {
    const principal = validateAdminCredential(readPrivateJson("/input/admin.json", "admin_credentials_json"), context.manifest);
    return {...context, credentials: {principals: {admin: principal}}};
}

function loadFrontendContext(context, {artifact = false} = {}) {
    const credentials = validateFrontendCredentials(readPrivateJson("/input/frontend.json", "frontend_credentials_json"), context.manifest);
    const result = {...context, credentials};
    if (artifact) {
        const sourceBytes = fs.readFileSync("/input/true_family_brt_probe.mjs");
        gate(sourceBytes.length === context.manifest.artifact.byte_length && sha256Bytes(sourceBytes) === context.manifest.artifact.sha256, "artifact_binding");
        result.sourceBytes = sourceBytes;
    }
    return result;
}

function loadObserverContext(context, {artifact = false} = {}) {
    const principal = validateObserverCredential(readPrivateJson("/input/observer.json", "observer_credentials_json"), context.manifest);
    const result = {...context, credentials: {principals: {observer: principal}}};
    if (artifact) {
        const sourceBytes = fs.readFileSync("/input/true_family_brt_probe.mjs");
        gate(sourceBytes.length === context.manifest.artifact.byte_length && sha256Bytes(sourceBytes) === context.manifest.artifact.sha256, "artifact_binding");
        result.sourceBytes = sourceBytes;
    }
    return result;
}

async function runInstall(baseContext) {
    const context = loadAdminContext(baseContext);
    const frontend = {
        schema: "true-family-pass-b1a-frontend-credentials-v1",
        principals: Object.fromEntries(FRONTEND_PRINCIPALS.map((key) => [key, generatePrincipalCredential(context.manifest.principals[key])])),
        wrong_password: crypto.randomBytes(32).toString("base64url"),
    };
    const observer = {
        schema: "true-family-pass-b1a-observer-credential-v1",
        principal: generatePrincipalCredential(context.manifest.principals.observer),
    };
    validateFrontendCredentials(frontend, context.manifest);
    validateObserverCredential(observer, context.manifest);
    const allPasswords = [
        context.credentials.principals.admin.password,
        frontend.wrong_password,
        ...Object.values(frontend.principals).map((item) => item.password),
        observer.principal.password,
    ];
    gate(new Set(allPasswords).size === allPasswords.length, "install_password_uniqueness");
    writePrivateJson(`${context.outputDir}/frontend.json`, frontend);
    writePrivateJson(`${context.outputDir}/observer-before.json`, observer);
    const control = await createControl(context);
    try {
        await installPolicy(context, control, {principals: frontend.principals, observer: observer.principal});
        return {
            schema: RUNTIME_SCHEMA,
            result: "pass",
            phase: "install",
            security: processSecurity(),
            control: {correlation_data_unique: true, command_success_from_response_not_puback: true, response_count: control.correlations.size},
            broker_policy_sha256: context.manifest.policy.canonical_sha256,
            generated_credentials: {frontend_without_admin_or_observer: true, observer_separate: true, passwords_emitted: false},
            observer_prepared: true,
            admin_bootstrap_role_narrowed: true,
        };
    } finally {
        await control.client.close();
    }
}

async function requireObserverPresent(context, control) {
    const client = await controlCommand(control, {command: "getClient", username: context.manifest.principals.observer.username});
    const role = await controlCommand(control, {command: "getRole", rolename: context.manifest.policy.observer_role.rolename});
    gate(normalizeClient(client.client).clientid === context.manifest.principals.observer.client_id, "observer_presence");
    gate(normalizeRole(role.role).rolename === context.manifest.policy.observer_role.rolename, "observer_presence");
}

async function runAdminReadback(baseContext) {
    const context = loadAdminContext(baseContext);
    const control = await createControl(context);
    try {
        let observerTransition;
        if (context.mode === "readback_before" || context.mode === "readback_final") {
            await requireObserverPresent(context, control);
            await deleteObserver(context, control);
            observerTransition = "revoked";
        }
        const observed = await readback(control, expectedReadbackFromManifest(context.manifest));
        if (context.mode === "readback_after") {
            const observer = {
                schema: "true-family-pass-b1a-observer-credential-v1",
                principal: generatePrincipalCredential(context.manifest.principals.observer),
            };
            validateObserverCredential(observer, context.manifest);
            writePrivateJson(`${context.outputDir}/observer-after.json`, observer);
            await createObserver(context, control, observer.principal);
            observerTransition = "prepared";
        }
        return {
            schema: RUNTIME_SCHEMA,
            result: "pass",
            phase: context.mode,
            security: processSecurity(),
            control: {correlation_data_unique: true, command_success_from_response_not_puback: true, response_count: control.correlations.size},
            observer_transition: observerTransition,
            admin_role_narrow: true,
            readback: observed.normalized,
            readback_sha256: observed.digest,
        };
    } finally {
        await control.client.close();
    }
}

async function runClientBefore(baseContext) {
    const context = loadFrontendContext(baseContext, {artifact: true});
    const network = await runClientBeforePhase("network", () => proveFrontendIsolation());
    const authentication = await runClientBeforePhase("authentication", () => authenticationMatrix(context));
    const publish = await runClientBeforePhase("publish_matrix", () => publishMatrix(context));
    const subscribe = await runClientBeforePhase("subscribe_matrix", () => subscribeMatrix(context));
    const source = await runClientBeforePhase("source_privacy", () => sourcePrivacyFrontend(context));
    await runClientBeforePhase("retained_control", async () => gate(await proveRequestTopicsNotRetained(context), "request_retained_final"));
    return {
        schema: RUNTIME_SCHEMA,
        result: "pass",
        phase: "client_before",
        security: processSecurity(),
        network,
        authentication,
        matrix: {publish, subscribe},
        enforcement: {
            gateway_exact_enforcement: true,
            deep_containment: true,
            qos_enforced: true,
            qos2_stateful_proxy: true,
            retain_enforced: true,
            pure_oracle_matrix_equivalent: true,
            composite_equivalence_tested: true,
            broker_native_qos_retain: false,
        },
        source,
        request_topics_retained_absent: true,
    };
}

async function runClientAfter(baseContext) {
    const context = loadFrontendContext(baseContext);
    const network = await proveFrontendIsolation();
    const authentication = await authenticationMatrix(context);
    const z2m = await openPrincipal(context, "z2m");
    try {
        const marker = Buffer.from("b1a-post-restart-source-control", "utf8");
        const ack = await z2m.publish(context.manifest.topics.source, marker, {qos: 1, retain: false});
        gate(publishResultSucceeded(ack), "restart_source_control_publish");
    } finally {
        await z2m.close();
    }
    gate(await proveRequestTopicsNotRetained(context), "restart_request_retained");
    return {
        schema: RUNTIME_SCHEMA,
        result: "pass",
        phase: "client_after",
        security: processSecurity(),
        network,
        authentication,
        gateway_broker_path: true,
        nonretained_source_positive_control: true,
        request_topics_retained_absent: true,
    };
}

async function runClientFinal(baseContext) {
    const context = loadFrontendContext(baseContext);
    const network = await proveFrontendIsolation();
    const authentication = await authenticationMatrix(context);
    const z2m = await openPrincipal(context, "z2m");
    try {
        const marker = Buffer.from("b1a-second-restart-source-control", "utf8");
        gate(publishResultSucceeded(await z2m.publish(context.manifest.topics.source, marker, {qos: 1, retain: false})), "final_source_control_publish");
    } finally {
        await z2m.close();
    }
    gate(await proveRequestTopicsNotRetained(context), "final_request_retained");
    return {
        schema: RUNTIME_SCHEMA,
        result: "pass",
        phase: "client_final",
        security: processSecurity(),
        network,
        authentication,
        gateway_broker_path: true,
        nonretained_source_positive_control: true,
        request_topics_retained_absent: true,
    };
}

async function runReadiness(baseContext) {
    const context = loadAdminContext(baseContext);
    const deadline = Date.now() + 10_000;
    let attempts = 0;
    while (Date.now() < deadline && attempts < 100) {
        attempts += 1;
        const client = new MqttClient(principalOptions(context, "admin"));
        try {
            const connack = await client.open();
            if (connack.reason === 0) {
                await client.ping();
                return {
                    schema: RUNTIME_SCHEMA,
                    result: "pass",
                    phase: context.mode,
                    security: processSecurity(),
                    authenticated_mqtt_v5_ready: true,
                    non_secret_result: true,
                    attempts,
                };
            }
        } catch {
            // Readiness retries expose only the final bounded result.
        } finally {
            await client.close();
        }
        blockingDelay(100);
    }
    throw new B1AFailure("broker_readiness");
}

async function runBackendBefore(baseContext) {
    const context = loadFrontendContext(baseContext);
    const z2m = await openPrincipal(context, "z2m");
    const outsideTopic = context.manifest.topics.native_outside;
    const sentinelTopic = context.manifest.topics.native_retained_sentinel;
    const outsidePayload = Buffer.from("b1a-native-outside-qos2", "utf8");
    const sentinelPayload = Buffer.from("b1a-retained-persistence-sentinel", "utf8");
    try {
        gate((await z2m.subscribe([{filter: outsideTopic, qos: 2}])).reasons[0] === 2, "backend_z2m_outside_subscribe");
        gate(publishResultSucceeded(await z2m.publish(outsideTopic, outsidePayload, {qos: 2, retain: true})), "backend_z2m_outside_publish");
        const outside = await z2m.message(outsideTopic);
        gate(outside.qos === 2 && outside.payload.equals(outsidePayload), "backend_z2m_outside_delivery");
        gate(publishResultSucceeded(await z2m.publish(outsideTopic, Buffer.alloc(0), {qos: 2, retain: true})), "backend_z2m_outside_clear");
        gate(publishResultSucceeded(await z2m.publish(sentinelTopic, sentinelPayload, {qos: 2, retain: true})), "backend_sentinel_publish");
    } finally {
        await z2m.close();
    }

    const requestTopic = context.manifest.topics.arm_request;
    const requestPayload = Buffer.from("b1a-native-envelope-gap", "utf8");
    const receiver = await openPrincipal(context, "z2m");
    const orchestrator = await openPrincipal(context, "orchestrator");
    try {
        gate((await receiver.subscribe([{filter: requestTopic, qos: 2}])).reasons[0] === 2, "backend_request_subscribe");
        gate(publishResultSucceeded(await orchestrator.publish(requestTopic, requestPayload, {qos: 0, retain: true})), "backend_native_envelope_publish");
        gate((await receiver.message(requestTopic)).payload.equals(requestPayload), "backend_native_envelope_delivery");
        await receiver.close();
        const replayReceiver = await openPrincipal(context, "z2m");
        try {
            gate((await replayReceiver.subscribe([{filter: requestTopic, qos: 2}])).reasons[0] === 2, "backend_request_replay_subscribe");
            const replay = await replayReceiver.message(requestTopic);
            gate(replay.retain === true && replay.payload.equals(requestPayload), "backend_native_retain_replay");
        } finally {
            await replayReceiver.close();
        }
        gate(publishResultSucceeded(await orchestrator.publish(requestTopic, Buffer.alloc(0), {qos: 1, retain: true})), "backend_native_envelope_clear");
    } finally {
        await orchestrator.close();
        await receiver.close();
    }

    const other = await openPrincipal(context, "other");
    try {
        const deniedPublish = await other.publish(outsideTopic, Buffer.from("denied", "utf8"), {qos: 1, retain: false});
        gate(!publishResultSucceeded(deniedPublish), "backend_other_publish_denied");
    } finally {
        await other.close();
    }
    const otherSubscriber = await openPrincipal(context, "other");
    try {
        gate((await otherSubscriber.subscribe([{filter: outsideTopic, qos: 2}])).reasons[0] >= 0x80, "backend_other_subscribe_denied");
    } finally {
        await otherSubscriber.close();
    }
    const collector = await openPrincipal(context, "collector");
    try {
        gate((await collector.subscribe([{filter: context.manifest.topics.source, qos: 2}])).reasons[0] >= 0x80, "backend_collector_source_denied");
    } finally {
        await collector.close();
    }
    return {
        schema: RUNTIME_SCHEMA,
        result: "pass",
        phase: "backend_before",
        security: processSecurity(),
        backend_only_application_credentials: true,
        native_acl_samples: {
            z2m_outside_publish_qos2_retain: true,
            z2m_outside_subscribe_qos2: true,
            orchestrator_native_qos_retain_not_enforced: true,
            other_publish_denied: true,
            other_subscribe_denied: true,
            collector_source_subscribe_denied: true,
        },
        retained_sentinel_published_qos2: true,
        retained_sentinel_payload_sha256: sha256Bytes(sentinelPayload),
    };
}

async function runBackendAfter(baseContext) {
    const context = loadFrontendContext(baseContext);
    const sentinelTopic = context.manifest.topics.native_retained_sentinel;
    const sentinelPayload = Buffer.from("b1a-retained-persistence-sentinel", "utf8");
    const z2m = await openPrincipal(context, "z2m");
    try {
        gate((await z2m.subscribe([{filter: sentinelTopic, qos: 2}])).reasons[0] === 2, "backend_sentinel_subscribe");
        const replay = await z2m.message(sentinelTopic);
        gate(replay.retain === true && replay.qos === 2 && replay.payload.equals(sentinelPayload), "backend_sentinel_replay");
        gate(publishResultSucceeded(await z2m.publish(sentinelTopic, Buffer.alloc(0), {qos: 2, retain: true})), "backend_sentinel_clear");
    } finally {
        await z2m.close();
    }
    const fresh = await openPrincipal(context, "z2m");
    try {
        gate((await fresh.subscribe([{filter: sentinelTopic, qos: 2}])).reasons[0] === 2, "backend_sentinel_clear_subscribe");
        await fresh.noMessage(sentinelTopic, 350);
    } finally {
        await fresh.close();
    }
    return {
        schema: RUNTIME_SCHEMA,
        result: "pass",
        phase: "backend_after",
        security: processSecurity(),
        backend_only_application_credentials: true,
        retained_sentinel_replayed_after_restart_qos2: true,
        retained_sentinel_cleared_qos2: true,
        retained_sentinel_immediately_absent: true,
        retained_sentinel_payload_sha256: sha256Bytes(sentinelPayload),
    };
}

async function runBackendFinal(baseContext) {
    const context = loadFrontendContext(baseContext);
    const sentinelTopic = context.manifest.topics.native_retained_sentinel;
    const z2m = await openPrincipal(context, "z2m");
    try {
        gate((await z2m.subscribe([{filter: sentinelTopic, qos: 2}])).reasons[0] === 2, "backend_final_subscribe");
        await z2m.noMessage(sentinelTopic, 500);
        const payload = Buffer.from("b1a-native-final-control", "utf8");
        gate(publishResultSucceeded(await z2m.publish(sentinelTopic, payload, {qos: 2, retain: false})), "backend_final_publish");
        gate((await z2m.message(sentinelTopic)).payload.equals(payload), "backend_final_delivery");
    } finally {
        await z2m.close();
    }
    return {
        schema: RUNTIME_SCHEMA,
        result: "pass",
        phase: "backend_final",
        security: processSecurity(),
        backend_only_application_credentials: true,
        retained_sentinel_absent_after_clear_and_second_restart: true,
        positive_nonretained_qos2_control: true,
    };
}

async function runtimeMain() {
    const context = runtimeContext();
    if (context.mode === "gateway") return runGateway(context.manifest);
    if (context.mode === "install") return runInstall(context);
    if (context.mode === "client_before") return runClientBefore(context);
    if (context.mode === "client_after") return runClientAfter(context);
    if (context.mode === "client_final") return runClientFinal(context);
    if (context.mode.startsWith("readiness")) return runReadiness(context);
    if (context.mode === "backend_before") return runBackendBefore(context);
    if (context.mode === "backend_after") return runBackendAfter(context);
    if (context.mode === "backend_final") return runBackendFinal(context);
    if (context.mode === "observer_before") return runObserverBefore(loadObserverContext(context, {artifact: true}));
    if (context.mode === "observer_after") return runObserverAfter(loadObserverContext(context));
    return runAdminReadback(context);
}

async function registerTests() {
    const {default: test} = await import("node:test");
    const {strict: assert} = await import("node:assert");
    const manifest = readJson(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../fixtures/physical_probe_pass_b1_manifest.json"), "test_manifest");

    test("MQTT variable integers round-trip at every encoding boundary", () => {
        for (const value of [0, 1, 127, 128, 16_383, 16_384, 2_097_151, 2_097_152, 268_435_455]) {
            const encoded = encodeVarInt(value);
            assert.deepEqual(decodeVarInt(encoded), {value, bytes: encoded.length});
        }
    });

    test("MQTT variable integers reject truncation, overlong encodings, and range drift", () => {
        for (const bytes of [Buffer.from([0x80]), Buffer.from([0x80, 0]), Buffer.from([0xff, 0xff, 0xff, 0xff, 0x00])]) {
            assert.throws(() => decodeVarInt(bytes), B1AFailure);
        }
        assert.throws(() => encodeVarInt(268_435_456), B1AFailure);
    });

    test("packet framing rejects trailing, truncated, and oversized bodies", () => {
        const valid = packet(12, 0, Buffer.alloc(0));
        assert.deepEqual(parsePacketFrame(valid), {type: 12, flags: 0, body: Buffer.alloc(0)});
        assert.throws(() => parsePacketFrame(Buffer.from([0xc0, 1])), B1AFailure);
        assert.throws(() => parsePacketFrame(Buffer.from([0xc0, 0, 0])), B1AFailure);
        assert.throws(() => parsePacketFrame(Buffer.from([0xc1, 0])), B1AFailure);
    });

    test("property parser accepts bounded correlation data and rejects unknown or malformed data", () => {
        const correlation = Buffer.from("correlation");
        const body = Buffer.concat([encodeVarInt(correlation.length + 3), Buffer.from([0x09]), mqttBinary(correlation)]);
        const parsed = parseProperties(body, 0, body.length);
        assert.equal(parsed.values[0].identifier, 0x09);
        assert.deepEqual(parsed.values[0].value, correlation);
        assert.throws(() => parseProperties(Buffer.from([1, 0x7f]), 0, 2), B1AFailure);
        assert.throws(() => parseProperties(Buffer.from([2, 0x09, 0]), 0, 3), B1AFailure);
    });

    test("CONNECT and CONNACK preserve exact MQTT v5 auth and session fields", () => {
        const connect = parsePacketFrame(encodeConnect({clientId: "client", username: "user", password: "password", cleanStart: false, sessionExpiry: 60}));
        assert.equal(connect.type, 1);
        assert.equal(connect.body.includes(Buffer.from("password")), true);
        assert.deepEqual(parseConnack(Buffer.from([1, 0, 0])), {sessionPresent: true, reason: 0, properties: []});
    });

    test("DISCONNECT accepts compact MQTT v5 forms and validates reasons and properties", () => {
        assert.deepEqual(parseDisconnect(Buffer.alloc(0)), {reason: 0});
        assert.deepEqual(parseDisconnect(Buffer.from([0x8e])), {reason: 0x8e});
        assert.deepEqual(parseDisconnect(Buffer.from([0x8e, 0])), {reason: 0x8e, properties: []});
        assert.throws(() => parseDisconnect(Buffer.from([0x01])), B1AFailure);
        assert.throws(() => parseDisconnect(Buffer.from([0x8e, 0x80])), B1AFailure);
    });

    test("CONNECT rejects malformed Unicode and partial authentication", () => {
        assert.throws(() => encodeConnect({clientId: "bad\0id"}), B1AFailure);
        assert.throws(() => encodeConnect({clientId: "client", username: "user"}), B1AFailure);
        assert.throws(() => encodeConnect({clientId: "\ud800"}), B1AFailure);
    });

    test("gateway CONNECT parsing retains only identity metadata after password-bearing transit", () => {
        const secret = "gateway-password-redaction-canary";
        const frame = encodeConnect({
            clientId: manifest.principals.orchestrator.client_id,
            username: manifest.principals.orchestrator.username,
            password: secret,
        });
        const parsed = parseConnectFrame(frame);
        assert.equal(frame.includes(Buffer.from(secret)), true);
        assert.equal(frontendPrincipalForConnect(manifest, parsed), "orchestrator");
        assert.equal(JSON.stringify(parsed).includes(secret), false);
        assert.deepEqual(Object.keys(parsed).sort(), ["cleanStart", "clientId", "keepalive", "passwordPresent", "sessionExpiry", "username"].sort());
        assert.equal(frontendPrincipalForConnect(manifest, {...parsed, clientId: manifest.authentication.wrong_client_id}), undefined);
    });

    test("streaming gateway parser handles fragmented and coalesced canonical frames", () => {
        const connect = encodeConnect({clientId: "client", username: "user", password: "password"});
        const ping = packet(12, 0, Buffer.alloc(0));
        const stream = new MqttFrameStream();
        assert.deepEqual(stream.push(connect.subarray(0, 1)), []);
        assert.deepEqual(stream.push(connect.subarray(1, 5)), []);
        assert.deepEqual(stream.push(Buffer.concat([connect.subarray(5), ping])), [connect, ping]);
        assert.throws(() => new MqttFrameStream().push(Buffer.from([0xc0, 0x80, 0x00])), B1AFailure);
        const isolated = new MqttFrameStream();
        assert.equal(gatewayConnectBatchIsIsolated(isolated.push(connect), isolated), true);
        const coalesced = new MqttFrameStream();
        assert.equal(gatewayConnectBatchIsIsolated(coalesced.push(Buffer.concat([connect, ping])), coalesced), false);
        const residual = new MqttFrameStream();
        assert.equal(gatewayConnectBatchIsIsolated(residual.push(Buffer.concat([connect, ping.subarray(0, 1)])), residual), false);
        assert.equal(gatewayBackendConnectMayForward("connecting_backend", false), true);
        assert.equal(gatewayBackendConnectMayForward("connecting_backend", true), false);
        assert.equal(gatewayBackendConnectMayForward("rejected", false), false);
        assert.equal(gatewayPreConnackBufferIsEmpty(0), true);
        assert.equal(gatewayPreConnackBufferIsEmpty(1), false);
    });

    test("topic oracle matches preflight boundaries and preserves internal empty segments", () => {
        assert.equal(topicContractValid("zigbee2mqtt/a//b"), true);
        assert.equal(topicContractValid("zigbee2mqtt/valid"), true);
        assert.equal(topicContractValid(`zigbee2mqtt/${"a".repeat(244)}`), true);
        assert.equal(topicContractValid(`zigbee2mqtt/${"\ud83d\ude00".repeat(244)}`), true);
        assert.equal(manifest.topic_oracle.schema, "true-family-pass-b1a-topic-oracle-v1");
        for (const topic of manifest.topic_oracle.valid_topics) assert.equal(topicContractValid(topic), true);
        for (const codepoint of manifest.topic_oracle.valid_codepoints) assert.equal(topicContractValid(`safe/${String.fromCodePoint(codepoint)}/topic`), true);
        for (const topic of manifest.topic_oracle.invalid_topics) assert.equal(topicContractValid(topic), false);
        for (const codepoint of manifest.topic_oracle.invalid_codepoints) assert.equal(topicContractValid(`safe/${String.fromCodePoint(codepoint)}/topic`), false);
        for (let codepoint = 0xd800; codepoint < 0xe000; codepoint += 1) assert.equal(topicContractValid(`safe/${String.fromCharCode(codepoint)}/topic`), false);
        for (let codepoint = 0xfdd0; codepoint < 0xfdf0; codepoint += 1) assert.equal(topicContractValid(`safe/${String.fromCodePoint(codepoint)}/topic`), false);
        for (let plane = 0; plane <= 16; plane += 1) {
            for (const ending of [0xfffe, 0xffff]) assert.equal(topicContractValid(`safe/${String.fromCodePoint(plane * 0x10000 + ending)}/topic`), false);
        }
        for (const invalid of ["", "/zigbee2mqtt", "zigbee2mqtt/", " zigbee2mqtt", "zigbee2mqtt ", "\u0085zigbee2mqtt", "zigbee2mqtt/+", "zigbee2mqtt/#", `zigbee2mqtt/${"a".repeat(245)}`, "zigbee2mqtt/\u0001bad"]) {
            assert.equal(topicContractValid(invalid), false);
        }
        assert.equal(topicContractValid("cafe\u0301/topic"), true);
        assert.equal(topicContractValid("caf\u00e9/topic"), true);
    });

    test("gateway denies adjacent bridge request at arbitrary depth", () => {
        for (const depth of [0, 8, 32, 100]) {
            const prefix = depth === 0 ? "" : `${Array.from({length: depth}, () => "a").join("/")}/`;
            const topic = `zigbee2mqtt/${prefix}bridge/request/action`;
            assert.equal(topicContractValid(topic), true);
            assert.equal(containsBridgeRequest(topic), true);
            assert.equal(gatewayAllowsPublish(manifest, "z2m", {topic, qos: 1, retain: false}), false);
        }
        assert.equal(containsBridgeRequest("zigbee2mqtt/bridge//request/action"), false);
    });

    test("gateway enforces orchestrator QoS and retain without forging broker success", () => {
        const topic = manifest.topics.arm_request;
        assert.equal(gatewayAllowsPublish(manifest, "orchestrator", {topic, qos: 1, retain: false}), true);
        assert.equal(gatewayAllowsPublish(manifest, "orchestrator", {topic, qos: 0, retain: false}), false);
        assert.equal(gatewayAllowsPublish(manifest, "orchestrator", {topic, qos: 1, retain: true}), false);
        assert.equal(gatewayAllowsPublish(manifest, "collector", {topic, qos: 1, retain: false}), false);
    });

    test("gateway subscription policy rejects wildcard, shared, source, and candidate access", () => {
        assert.equal(gatewayAllowsSubscribe(manifest, "z2m", "zigbee2mqtt/#"), true);
        assert.equal(gatewayAllowsSubscribe(manifest, "z2m", "zigbee2mqtt/a//b"), true);
        assert.equal(gatewayAllowsSubscribe(manifest, "z2m", "zigbee2mqtt/+"), false);
        assert.equal(gatewayAllowsSubscribe(manifest, "orchestrator", manifest.topics.status), true);
        assert.equal(gatewayAllowsSubscribe(manifest, "orchestrator", manifest.topics.source), false);
        assert.equal(gatewayAllowsSubscribe(manifest, "collector", manifest.topics.candidate_friendly), false);
        assert.equal(gatewayAllowsSubscribe(manifest, "collector", `$share/b1a/${manifest.scope.base_topic}/#`), false);
        assert.equal(gatewayAllowsSubscribe(manifest, "z2m", "$share/b1a/outside/root"), false);
    });

    test("gateway fails closed on malformed, unsupported, and backend-loss states", () => {
        assert.throws(() => validateGatewayClientFrame(packet(15, 0, Buffer.alloc(0)), manifest, "z2m"), B1AFailure);
        const invalidTopicBody = Buffer.concat([u16(1), Buffer.from([0xff]), u16(1), Buffer.from([0])]);
        assert.throws(() => validateGatewayClientFrame(packet(3, 2, invalidTopicBody), manifest, "z2m"), B1AFailure);
        assert.throws(() => validateGatewayClientFrame(encodeRawFilterSubscribe(1, Buffer.from([0xff])), manifest, "z2m"), B1AFailure);
        assert.equal(gatewayBackendDisconnectFatal({state: "active", clientClosing: false, brokerClosing: false, clientDestroyed: false}), true);
        assert.equal(gatewayBackendDisconnectFatal({state: "closing", clientClosing: true, brokerClosing: false, clientDestroyed: false}), false);
        assert.equal(gatewayUpstreamErrorFatal("active"), true);
        assert.equal(gatewayUpstreamErrorFatal("closed"), false);
    });

    test("SUBACK parser preserves explicit success and denial reasons", () => {
        const parsed = parseSuback(Buffer.from([0, 7, 0, 0, 1, 2, 0x87]));
        assert.deepEqual(parsed, {packetId: 7, reasons: [0, 1, 2, 0x87], properties: []});
        assert.throws(() => parseSuback(Buffer.from([0, 7, 0])), B1AFailure);
    });

    test("PUBACK parser distinguishes success from broker denial", () => {
        assert.deepEqual(parsePuback(Buffer.from([0, 1])), {packetId: 1, reason: 0, properties: []});
        assert.deepEqual(parsePuback(Buffer.from([0, 2, 0x10])), {packetId: 2, reason: 0x10, properties: []});
        assert.deepEqual(parsePuback(Buffer.from([0, 3, 0x10, 0])), {packetId: 3, reason: 0x10, properties: []});
        assert.deepEqual(parsePuback(Buffer.from([0, 2, 0x87, 0])), {packetId: 2, reason: 0x87, properties: []});
        assert.equal(reasonClass(0x87), "not_authorized");
        assert.equal(reasonClass(0x10), "success");
    });

    test("QoS2 acknowledgements accept minimal forms and proxy in exact order", () => {
        assert.deepEqual(parsePubrec(Buffer.from([0, 7])), {packetId: 7, reason: 0, properties: []});
        assert.deepEqual(parsePubrec(Buffer.from([0, 7, 0x10])), {packetId: 7, reason: 0x10, properties: []});
        assert.deepEqual(parsePubrel(Buffer.from([0, 7])), {packetId: 7, reason: 0, properties: []});
        assert.deepEqual(parsePubcomp(Buffer.from([0, 7, 0, 0])), {packetId: 7, reason: 0, properties: []});
        const state = qos2State();
        validateGatewayClientFrame(encodePublish("outside/root", Buffer.from("qos2"), {qos: 2, packetId: 7}), manifest, "z2m", state);
        validateGatewayBrokerFrame(encodePubrec(7), state);
        validateGatewayClientFrame(encodePubrel(7), manifest, "z2m", state);
        validateGatewayBrokerFrame(encodePubcomp(7), state);
        assert.equal(state.clientPublishes.get(7).state, "completed");
        const brokerPublish = encodePublish("outside/root", Buffer.from("qos2"), {qos: 2, packetId: 9});
        validateGatewayBrokerFrame(brokerPublish, state);
        validateGatewayClientFrame(encodePubrec(9), manifest, "z2m", state);
        validateGatewayBrokerFrame(encodePubrel(9), state);
        validateGatewayClientFrame(encodePubcomp(9), manifest, "z2m", state);
        assert.equal(state.brokerPublishes.get(9).state, "completed");
        assert.throws(() => validateGatewayClientFrame(encodePubrel(10), manifest, "z2m", state), B1AFailure);
    });

    test("QoS2 DUP PUBLISH races preserve immutable identity and reject stale reuse", () => {
        const state = qos2State();
        const original = encodePublish("outside/root", Buffer.from("immutable"), {qos: 2, retain: false, packetId: 31});
        const duplicate = encodePublish("outside/root", Buffer.from("immutable"), {qos: 2, retain: false, duplicate: true, packetId: 31});
        validateGatewayClientFrame(original, manifest, "z2m", state);
        validateGatewayClientFrame(duplicate, manifest, "z2m", state);
        validateGatewayBrokerFrame(encodePubrec(31), state);
        validateGatewayClientFrame(duplicate, manifest, "z2m", state);
        validateGatewayBrokerFrame(encodePubrec(31), state);
        assert.throws(() => validateGatewayClientFrame(encodePublish("outside/root", Buffer.from("changed"), {qos: 2, duplicate: true, packetId: 31}), manifest, "z2m", state), B1AFailure);
        assert.throws(() => validateGatewayClientFrame(encodePublish("outside/changed", Buffer.from("immutable"), {qos: 2, duplicate: true, packetId: 31}), manifest, "z2m", state), B1AFailure);
        assert.throws(() => validateGatewayClientFrame(encodePublish("outside/root", Buffer.from("immutable"), {qos: 2, retain: true, duplicate: true, packetId: 31}), manifest, "z2m", state), B1AFailure);
        assert.throws(() => validateGatewayClientFrame(encodePublish("outside/root", Buffer.from("immutable"), {qos: 1, duplicate: true, packetId: 31}), manifest, "z2m", state), B1AFailure);
        validateGatewayClientFrame(encodePubrel(31), manifest, "z2m", state);
        validateGatewayBrokerFrame(encodePubcomp(31), state);
        assert.throws(() => validateGatewayClientFrame(duplicate, manifest, "z2m", state), B1AFailure);
        validateGatewayClientFrame(original, manifest, "z2m", state);

        const brokerState = qos2State();
        validateGatewayBrokerFrame(original, brokerState);
        validateGatewayBrokerFrame(duplicate, brokerState);
        validateGatewayClientFrame(encodePubrec(31), manifest, "z2m", brokerState);
        validateGatewayBrokerFrame(duplicate, brokerState);
        validateGatewayClientFrame(encodePubrec(31), manifest, "z2m", brokerState);
        assert.throws(() => validateGatewayBrokerFrame(encodePublish("outside/root", Buffer.from("changed"), {qos: 2, duplicate: true, packetId: 31}), brokerState), B1AFailure);
        validateGatewayBrokerFrame(encodePubrel(31), brokerState);
        validateGatewayClientFrame(encodePubcomp(31), manifest, "z2m", brokerState);
        assert.throws(() => validateGatewayBrokerFrame(duplicate, brokerState), B1AFailure);
    });

    test("MQTT QoS2 publish requires successful PUBREC and PUBCOMP", async () => {
        const client = new MqttClient({});
        client.socket = {write: () => true};
        let response = 0;
        client._next = async () => response++ === 0
            ? {type: 5, value: {packetId: 1, reason: 0, properties: []}}
            : {type: 7, value: {packetId: 1, reason: 0x92, properties: []}};
        const result = await client.publish("outside/root", Buffer.from("qos2"), {qos: 2});
        assert.equal(result.pubrec_reason, 0);
        assert.equal(result.pubcomp_reason, 0x92);
        assert.equal(publishResultSucceeded(result), false);
        assert.equal(publishResultSucceeded({qos: 2, pubrec_reason: 0x10, pubcomp_reason: 0}), true);
    });

    test("PUBLISH parser preserves QoS, retain, packet id, properties, and payload", () => {
        const encoded = encodePublish("topic/value", Buffer.from("payload"), {qos: 1, retain: true, packetId: 9, properties: [{identifier: 0x09, value: Buffer.from("id")}]});
        const frame = parsePacketFrame(encoded);
        const parsed = parsePublish(frame.flags, frame.body);
        assert.equal(parsed.qos, 1);
        assert.equal(parsed.retain, true);
        assert.equal(parsed.packetId, 9);
        assert.equal(parsed.payload.toString(), "payload");
        assert.deepEqual(parsed.properties[0].value, Buffer.from("id"));
    });

    test("PUBLISH accepts QoS2 and rejects wildcard topic names and reserved QoS", () => {
        assert.throws(() => encodePublish("topic/#", Buffer.alloc(0)), B1AFailure);
        const qos2 = parsePacketFrame(encodePublish("topic", Buffer.alloc(0), {qos: 2, packetId: 3}));
        assert.equal(parsePublish(qos2.flags, qos2.body).qos, 2);
        assert.throws(() => parsePublish(6, Buffer.alloc(0)), B1AFailure);
        assert.throws(() => parsePublish(8, Buffer.alloc(0)), B1AFailure);
    });

    test("denial history rejects any broker ACK or PUBLISH before close", () => {
        assert.equal(denialHistoryIsClean([{sequence: 2, type: 14}, {sequence: 3, type: "close"}], 1), true);
        for (const type of [2, 3, 4, 5, 6, 7, 9, 11]) {
            assert.equal(denialHistoryIsClean([{sequence: 2, type}, {sequence: 3, type: "close"}], 1), false);
        }
    });

    test("UNSUBSCRIBE and UNSUBACK are packet-aware and bounded", () => {
        const frame = parsePacketFrame(encodeUnsubscribe(4, ["topic/value"]));
        assert.equal(frame.type, 10);
        assert.deepEqual(parseUnsuback(Buffer.from([0, 4, 0, 0])), {packetId: 4, reasons: [0], properties: []});
    });

    test("subscription delivery controls use the policy-authorized publisher", () => {
        const context = {manifest: {topics: {request_topics: ["zigbee2mqtt/bridge/request/true_family/physical_probe"]}}};
        assert.equal(matrixPublisherPrincipal(context, "zigbee2mqtt/bridge/request/true_family/physical_probe"), "orchestrator");
        assert.equal(matrixPublisherPrincipal(context, "zigbee2mqtt/bridge/true_family/physical_probe/status"), "z2m");
    });

    test("canonical readback preserves sequence order and rejects missing, extra, or reordered objects", () => {
        const expected = {
            defaults: [
                {acltype: "publishClientSend", allow: false},
                {acltype: "subscribe", allow: false},
            ],
            anonymous_group: "",
            clients: [
                {username: "u", clientid: "c", disabled: false, roles: [], groups: []},
                {username: "v", clientid: "d", disabled: false, roles: [], groups: []},
            ],
            roles: [
                {
                    rolename: "r",
                    acls: [
                        {acltype: "publishClientSend", topic: "a", priority: 100, allow: true},
                        {acltype: "publishClientSend", topic: "b", priority: 90, allow: false},
                    ],
                },
                {rolename: "s", acls: []},
            ],
            groups: [],
        };
        const keyReordered = {
            groups: [],
            roles: [
                {
                    acls: [
                        {allow: true, priority: 100, topic: "a", acltype: "publishClientSend"},
                        {allow: false, priority: 90, topic: "b", acltype: "publishClientSend"},
                    ],
                    rolename: "r",
                },
                {acls: [], rolename: "s"},
            ],
            clients: [
                {groups: [], roles: [], disabled: false, clientid: "c", username: "u"},
                {groups: [], roles: [], disabled: false, clientid: "d", username: "v"},
            ],
            anonymous_group: "",
            defaults: [
                {allow: false, acltype: "publishClientSend"},
                {allow: false, acltype: "subscribe"},
            ],
        };
        assert.deepEqual(validateReadback(keyReordered, expected), expected);
        assert.throws(() => validateReadback({...keyReordered, clients: [...keyReordered.clients].reverse()}, expected), B1AFailure);
        assert.throws(() => validateReadback({...keyReordered, roles: [...keyReordered.roles].reverse()}, expected), B1AFailure);
        assert.throws(() => validateReadback({...keyReordered, roles: [{...keyReordered.roles[0], acls: [...keyReordered.roles[0].acls].reverse()}, keyReordered.roles[1]]}, expected), B1AFailure);
        assert.throws(() => validateReadback({...keyReordered, defaults: [...keyReordered.defaults].reverse()}, expected), B1AFailure);
        assert.throws(() => validateReadback({...keyReordered, clients: keyReordered.clients.slice(1)}, expected), B1AFailure);
        assert.throws(() => validateReadback({...keyReordered, extra: true}, expected), B1AFailure);
    });

    test("source inventory binds exact artifact bytes without changing source", () => {
        const source = fs.readFileSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../custom_components/true_family/probe/true_family_brt_probe.mjs"));
        const payload = buildSourceInventory(source);
        const parsed = JSON.parse(payload.toString("utf8"));
        assert.equal(parsed.length, 1);
        assert.equal(sha256Bytes(Buffer.from(parsed[0].code)), "1d40f5a0d8b01ad7e7eb6c92b52319285f76bdbff8abbff0b6743046258645c1");
        assert.equal(sha256Bytes(source), "1d40f5a0d8b01ad7e7eb6c92b52319285f76bdbff8abbff0b6743046258645c1");
    });

    test("reason, installer, and client-before failure classes never expose private detail", async () => {
        assert.equal(reasonClass(0), "success");
        assert.equal(reasonClass(0x86), "bad_username_or_password");
        assert.equal(reasonClass("closed"), "connection_closed");
        assert.equal(reasonClass(0x80), "negative_reason");
        for (const [code, category] of [
            ["runtime_environment", "context"],
            ["admin_credentials_json", "credentials"],
            ["control_connect", "broker_connect"],
            ["control_subscribe", "broker_subscribe"],
            ["mqtt_timeout", "command_transport"],
            ["control_response_error", "command_rejected"],
            ["container_security", "security"],
        ]) assert.equal(installFailureCategoryForCode(code), category);
        for (const value of [undefined, null, "", "toString", "__proto__", "CONTROL_RESPONSE_ERROR", "control_response_error\n/private/path", {code: "control_response_error"}]) {
            assert.equal(installFailureCategoryForCode(value), "unknown");
        }
        assert.equal(runtimeFailureCategory("install", new Error("control_response_error")), "unknown");
        assert.equal(runtimeFailureCategory("client_before", new B1AFailure("control_response_error")), "unknown");
        assert.equal(runtimeFailureCategory("install", new B1AFailure("control_response_error")), "command_rejected");
        for (const category of CLIENT_BEFORE_FAILURE_CATEGORIES.filter((value) => value !== "unknown")) {
            await assert.rejects(
                runClientBeforePhase(category, async () => { throw new B1AFailure("private/path\nunderlying"); }),
                (error) => runtimeFailureCategory("client_before", error) === category
                    && runtimeFailureRecord(runtimeFailureCategory("client_before", error)) === `${canonical({schema: FAILURE_SCHEMA, result: "fail", failure_category: category})}\n`
                    && !runtimeFailureRecord(runtimeFailureCategory("client_before", error)).includes("underlying"),
            );
        }
        await assert.rejects(
            runClientBeforePhase("network", async () => { throw new Error("private generic detail"); }),
            (error) => runtimeFailureCategory("client_before", error) === "unknown",
        );
        assert.equal(runtimeFailureCategory("client_before", {category: "network"}), "unknown");
        assert.equal(runtimeFailureRecord("command_rejected"), '{"failure_category":"command_rejected","result":"fail","schema":"true-family-pass-b1a-runtime-failure-v2"}\n');
        assert.equal(runtimeFailureRecord("retained_control"), '{"failure_category":"retained_control","result":"fail","schema":"true-family-pass-b1a-runtime-failure-v2"}\n');
        assert.equal(runtimeFailureRecord("/private/path\ncontrol_response_error"), '{"failure_category":"unknown","result":"fail","schema":"true-family-pass-b1a-runtime-failure-v2"}\n');
        assert.equal(runtimeFailureRecord("command_rejected").includes("control_response_error"), false);
    });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain && process.argv[2] === "--runtime") {
    try {
        const value = await runtimeMain();
        if (value !== undefined) {
            const output = `${canonical(value)}\n`;
            gate(Buffer.byteLength(output, "utf8") <= 128 * 1024, "runtime_output_size");
            process.stdout.write(output);
        }
    } catch (error) {
        if (process.env.B1A_MODE !== "gateway") process.stdout.write(runtimeFailureRecord(runtimeFailureCategory(process.env.B1A_MODE, error)));
        process.exitCode = 1;
    }
} else if (isMain) {
    await registerTests();
}
