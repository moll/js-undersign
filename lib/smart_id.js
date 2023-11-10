var _ = require("../lib/underscore")
var Certificate = require("./certificate")
var StandardError = require("standard-error")
var FetchError = require("fetch-error")
var fetchDefaults = require("fetch-defaults")
var sha256 = require("./crypto").hash.bind(null, "sha256")
var encode = encodeURIComponent
var URL = "https://rp-api.smart-id.com/v1/"
exports = module.exports = SmartId
exports.SmartIdError = SmartIdError
exports.SmartIdCertificate = SmartIdCertificate
exports.verification = verification

function SmartId(url, opts) {
	if (typeof url != "string") { opts = url; url = null }

	this.user = opts.user
	this.password = opts.password
	this.fetch = fetchDefaults(this.fetch, url || URL)
}

SmartId.prototype.fetch = fetchDefaults(require("./fetch"), {
	timeout: 20 * 1000,
	headers: {"Accept": "application/json"}
})

SmartId.prototype.request = function(url, opts) {
	return this.fetch(url, "json" in opts ? _.defaults({
		json: _.assign({
			relyingPartyName: this.user,
			relyingPartyUUID: this.password
		}, opts.json)
	}, opts) : opts)
}

SmartId.prototype.certificate = function(id, opts) {
	return this.request("certificatechoice/" + identify(id), {
		method: "POST",
		json: opts
	}).catch(handleFetchError.bind(null, "ACCOUNT_NOT_FOUND")).then((res) => (
		new SmartIdSession("certificate", res.body.sessionID, function(obj) {
			if (obj.state != "COMPLETE") return null

			var cert = new SmartIdCertificate(parseBase64(obj.cert.value))
			cert.smartId = obj.result.documentNumber
			cert.level = obj.cert.certificateLevel
			return cert
		})
	))
}

SmartId.prototype.authenticate = function(id, signableHash, opts) {
	return this.request("authentication/" + identify(id), {
		method: "POST",
		json: _.assign({
			hash: signableHash.toString("base64"),
			hashType: "SHA256"
		}, opts)
	}).catch(handleFetchError.bind(null, "ACCOUNT_NOT_FOUND")).then((res) => (
		new SmartIdSession("authentication", res.body.sessionID, parseSignature)
	))
}

SmartId.prototype.sign = function(id, signableHash, opts) {
	return this.request("signature/" + identify(id), {
		method: "POST",
		json: _.assign({
			hash: signableHash.toString("base64"),
			hashType: "SHA256"
		}, opts)
	}).catch(handleFetchError.bind(null, "ACCOUNT_NOT_FOUND")).then((res) => (
		new SmartIdSession("signature", res.body.sessionID, parseSignature)
	))
}

SmartId.prototype.wait = function(session, timeout) {
	var timeoutMs = timeout == null ? 90000 : timeout * 1000
	var url = "session/" + session.id + "?timeoutMs=" + timeoutMs
	var res = this.request(url, {timeout: timeoutMs + 5000})
	res = res.then(parse, handleFetchError.bind(null, "SESSION_NOT_FOUND"))
	res = res.then(session.parse)
	return res
}

exports.demo = new SmartId("https://sid.demo.sk.ee/smart-id-rp/v1/", {
	user: "DEMO",
	password: "00000000-0000-0000-0000-000000000000"
})

function SmartIdCertificate(der) {
	Certificate.call(this, der)
}

SmartIdCertificate.prototype = Object.create(Certificate.prototype, {
	constructor: {value: SmartIdCertificate, configurable: true, writeable: true}
})

SmartIdCertificate.prototype.smartId = null
SmartIdCertificate.prototype.level = null

function SmartIdSession(type, id, parse) {
	this.id = id
	this.type = type
	this.parse = parse
}

function SmartIdError(code, msg, props) {
	this.code = code
	StandardError.call(this, msg, props)
	if (this.response) Object.defineProperty(this, "response", {enumerable: !!0})
}

SmartIdError.prototype = Object.create(StandardError.prototype, {
	constructor: {value: SmartIdError, configurable: true, writeable: true}
})

// https://github.com/SK-EID/smart-id-documentation/blob/master/README.md#23132-computing-the-verification-code
function verification(signableHash) {
	var verifiableHash = sha256(signableHash)

	return (
		((verifiableHash[verifiableHash.length - 2]) << 8) +
		(verifiableHash[verifiableHash.length - 1])
	) % 10000
}

var ERROR_CODES = exports.ERROR_CODES = {
	400: "BAD_REQUEST",
	401: "UNAUTHORIZED",
	403: "FORBIDDEN",
	471: "NO_SUITABLE_CERTIFICATE",
	580: "MAINTENANCE"
}

var ERROR_MESSAGES = exports.ERROR_MESSAGES = {
	USER_REFUSED: "Person cancelled",
	TIMEOUT: "Person did not respond in time",
	DOCUMENT_UNUSABLE: "Person's certificate unusable",
	WRONG_VC: "Wrong verification code chosen"
}

function parse(res) {
	if (
		res.body.state == "RUNNING" ||
		res.body.state == "COMPLETE" && res.body.result.endResult == "OK"
	) return res.body

	var code = res.body.result.endResult
	throw new SmartIdError(code, ERROR_MESSAGES[code] || code, {response: res})
}

function parseSignature(obj) {
	if (obj.state != "COMPLETE") return null

	var cert = new SmartIdCertificate(parseBase64(obj.cert.value))
	cert.smartId = obj.result.documentNumber
	cert.level = obj.cert.certificateLevel
	return [cert, parseBase64(obj.signature.value)]
}

function handleFetchError(notFoundCode, err) {
	if (err instanceof FetchError && err.response) {
		var code = err.code == 404 ? notFoundCode : ERROR_CODES[err.code]
		if (code == null) throw err

		var res = err.response
		var msg = res.body && res.body.message || res.statusMessage
		throw new SmartIdError(code, msg, {response: res})
	}

	throw err
}

function identify(id) {
	if (id instanceof SmartIdCertificate) return "document/" + encode(id.smartId)
	return "etsi/" + encode(id)
}

function parseBase64(base64) { return Buffer.from(base64, "base64") }
