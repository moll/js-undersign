var _ = require("./underscore")
var X509Asn = require("./x509_asn")
var TimestampAsn = require("./timestamp_asn")
var TimestampRequestAsn = TimestampAsn.TimestampRequest
var TimestampResponseAsn = TimestampAsn.TimestampResponse
var fetch = require("./fetch")
var SIGNED_DATA_OID = TimestampAsn.SIGNED_DATA_OID
var SHA256_ALGORITHM = {algorithm: X509Asn.SHA256}
exports.TimestampResponse = TimestampResponse
exports.parse = parse

exports.read = function(url, digest) {
	return exports.request(url, digest).then(parse)
}

exports.request = function(url, digest) {
	var req = createRequest(digest)

	return fetch(url, {
		method: "POST",

		headers: {
			Accept:  "application/timestamp-reply",
			"Content-Type": "application/timestamp-query",
			"Content-Length": req.length
		},

		body: req
	}).then((res) => res.body)
}

function createRequest(digest) {
	return TimestampRequestAsn.encode({
		version: "v1",
		certReq: true,
		messageImprint: {hashAlgorithm: SHA256_ALGORITHM, hashedMessage: digest}
	})
}

function TimestampResponse(asn) {
	this.asn = asn

	// Status is defined in RFC 2510 under PKIStatus:
	// https://datatracker.ietf.org/doc/html/rfc2510#section-3.2.3
	this.status = asn.status.status

	// Every PKIFreeText[2] message in a TimeStampResp[1] should contain
	// a language tag, but I've yet to see one.
	//
	// [1]: https://datatracker.ietf.org/doc/html/rfc3161#section-2.4.2
	// [2]: https://tools.ietf.org/html/rfc2510#section-3.1.1
	this.message =
		asn.status.statusString && asn.status.statusString.join("; ") || null

	var type = asn.timeStampToken.contentType

	if (!_.deepEquals(type, SIGNED_DATA_OID)) throw new Error(
		`Token content type is not ${SIGNED_DATA_OID.join(".")}: ${type}`
	)
}

_.defineGetter(TimestampResponse.prototype, "token", function() {
	return TimestampAsn.ContentInfo.encode(this.asn.timeStampToken)
})

TimestampResponse.prototype.toBuffer = function() {
	return TimestampResponseAsn.encode(this.asn)
}

function parse(der) {
	return new TimestampResponse(TimestampResponseAsn.decode(der))
}
