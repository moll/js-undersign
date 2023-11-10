var _ = require("../lib/underscore")
var Certificate = require("./certificate")
var StandardError = require("standard-error")
var FetchError = require("fetch-error")
var fetchDefaults = require("fetch-defaults")
var URL = "https://mid.sk.ee/mid-api/"
exports = module.exports = MobileId
exports.MobileIdError = MobileIdError
exports.MobileIdSession = MobileIdSession
exports.confirmation = confirmation

function MobileId(url, opts) {
	if (url && typeof url == "object") { opts = url; url = null }

	this.user = opts.user
	this.password = opts.password
	this.fetch = fetchDefaults(this.fetch, url || URL)
}

MobileId.prototype.fetch = fetchDefaults(require("./fetch"), {
	timeout: 20 * 1000,
	headers: {"Accept": "application/json"}
})

MobileId.prototype.request = function(url, opts) {
	return this.fetch(url, "json" in opts ? _.defaults({
		json: _.assign({
			relyingPartyName: this.user,
			relyingPartyUUID: this.password
		}, opts.json)
	}, opts) : opts)
}

MobileId.prototype.certificate = function(phoneNumber, personalId) {
	return this.request("certificate", {
		method: "POST",
		json:  {phoneNumber: phoneNumber, nationalIdentityNumber: personalId}
	}).then(parse, handleFetchError).then((obj) => (
		new Certificate(parseBase64(obj.cert))
	))
}

MobileId.prototype.authenticate = function(
	phoneNumber,
	personalId,
	signableHash,
	opts
) {
	// The authentication endpoint seems to always return a session id. It's only
	// when requesting the session status do you get errors.
	return this.request("authentication", {
		method: "POST",
		json: _.assign({
			phoneNumber: phoneNumber,
			nationalIdentityNumber: personalId,
			hash: signableHash.toString("base64"),
			hashType: "SHA256",
			language: "EST"
		}, opts)
	}).then(
		(res) => new MobileIdSession("auth", res.body.sessionID),
		handleFetchError
	)
}

MobileId.prototype.sign = function(
	phoneNumber,
	personalId,
	signableHash,
	opts
) {
	// The signature endpoint seems to always return a session id. It's only when
	// requesting the session status do you get errors.
	return this.request("signature", {
		method: "POST",
		json: _.assign({
			phoneNumber: phoneNumber,
			nationalIdentityNumber: personalId,
			hash: signableHash.toString("base64"),
			hashType: "SHA256",
			language: "EST"
		}, opts)
	}).then(
		(res) => new MobileIdSession("sign", res.body.sessionID),
		handleFetchError
	)
}

MobileId.prototype.wait = function(session, timeout) {
	var timeoutMs = timeout == null ? 90000 : timeout * 1000
	var url = session.type == "auth" ? "authentication" : "signature"
	url += "/session/" + session.id + "?timeoutMs=" + timeoutMs
	var res = this.request(url, {timeout: timeoutMs + 5000})
	return res.then(parse, handleFetchError).then(session.parse.bind(session))
}

exports.demo = new MobileId("https://tsp.demo.sk.ee/mid-api/", {
	user: "DEMO",
	password: "00000000-0000-0000-0000-000000000000"
})

function MobileIdSession(type, id) {
	this.type = type
	this.id = id
}

MobileIdSession.prototype.toJSON = function() {
	return {type: this.type, id: this.id}
}

MobileIdSession.prototype.parse = function(obj) {
	if (obj.state != "COMPLETE") return null

	var signature = parseBase64(obj.signature.value)

	switch (this.type) {
		case "auth": return [new Certificate(parseBase64(obj.cert)), signature]

		// NOTE: The signature response doesn't include the certificate as it does
		// with the authentication response or with Smart-ID.
		case "sign": return signature
		default: throw new RangeError("Invalid session type: " + this.type)
	}
}

MobileIdSession.parse = function(obj) {
	return new MobileIdSession(obj.type, obj.id)
}

MobileIdSession.serialize = function(session) { return session.toJSON() }

function MobileIdError(code, msg, props) {
	this.code = code
	StandardError.call(this, msg, props)
	if (this.response) Object.defineProperty(this, "response", {enumerable: !!0})
}

MobileIdError.prototype = Object.create(StandardError.prototype, {
	constructor: {value: MobileIdError, configurable: true, writeable: true}
})

// https://github.com/SK-EID/MID#24-verification-code
// 6 bits from the beginning of the hash and 7 from the end, then concatenated.
function confirmation(signableHash) {
	return (
		((signableHash[0] & 0b11111100) << 5) +
		(signableHash[signableHash.length - 1] & 0b01111111)
	)
}

// https://github.com/SK-EID/MID/wiki/Test-number-for-automated-testing-in-DEMO
var ERROR_MESSAGES = exports.ERROR_MESSAGES = {
	// Certificate errors:
	// https://github.com/SK-EID/MID#317-possible-result-values
	//
	// There used to be a NOT_ACTIVE response code, but that was removed Sep 11,
	// 2020:
	// https://github.com/SK-EID/MID/commit/7dc8b4d7aabeb7765e83879d054d5e535a62a4bf
	NOT_FOUND: "Person is not a Mobile-Id user or personal id mismatch",

	// Signing errors:
	// https://github.com/SK-EID/MID#338-session-end-result-codes
	TIMEOUT: "Person did not respond in time",
	NOT_MID_CLIENT: "Person hasn't activated their certificates",
	USER_CANCELLED: "Person cancelled",
	SIGNATURE_HASH_MISMATCH: "Mobile-Id certificate differs from service provider's",
	PHONE_ABSENT: "Phone is unavailable",
	DELIVERY_ERROR: "Failed to send a message to the phone",
	SIM_ERROR: "SIM application error"
}

function parse(res) {
	if (res.body.state == "RUNNING" || res.body.result == "OK") return res.body
	var code = res.body.result
	throw new MobileIdError(code, ERROR_MESSAGES[code] || code, {response: res})
}

function handleFetchError(err) {
	if (err instanceof FetchError && err.response) {
		var res = err.response
		var msg = res.body && res.body.error || res.statusMessage
		var props = {response: res}

		if (err.code == 400) throw new MobileIdError("BAD_REQUEST", msg, props)
		if (err.code == 401) throw new MobileIdError("UNAUTHORIZED", msg, props)
	}

	throw err
}

function parseBase64(base64) { return Buffer.from(base64, "base64") }
