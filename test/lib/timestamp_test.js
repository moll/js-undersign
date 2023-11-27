var _ = require("../../lib/underscore")
var X509Asn = require("../../lib/x509_asn")
var Timestamp = require("../../lib/timestamp")
var TimestampResponse = Timestamp.TimestampResponse
var TimestampAsn = require("../../lib/timestamp_asn")
var TimestampRequestAsn = TimestampAsn.TimestampRequest
var TimestampResponseAsn = TimestampAsn.TimestampResponse
var wait = require("../../lib/promise").wait
var parseBody = require("../mitm").parseBody
var parse = TimestampResponseAsn.decode.bind(TimestampResponseAsn)
var serialize = TimestampResponseAsn.encode.bind(TimestampResponseAsn)
var DIGEST = Buffer.from("foobar")
var SIGNED_DATA_OID = TimestampAsn.SIGNED_DATA_OID

describe("Timestamp", function() {
	describe(".read", function() {
		require("../mitm")()

		it("must respond with timestamp", function*() {
			var timestamp = Timestamp.read("http://example.com/tsa", DIGEST)

			var req = yield wait(this.mitm, "request")
			req.headers.host.must.equal("example.com")
			req.headers["content-type"].must.equal("application/timestamp-query")
			req.headers.accept.must.equal("application/timestamp-reply")
			req.method.must.equal("POST")
			req.url.must.equal("/tsa")

			var asn = TimestampRequestAsn.decode(yield parseBody(req))
			asn.version.must.equal("v1")
			asn.messageImprint.hashAlgorithm.algorithm.must.eql(X509Asn.SHA256)
			asn.messageImprint.hashedMessage.must.eql(DIGEST)
			asn.certReq.must.be.true()

			var token = {
				contentType: SIGNED_DATA_OID,
				content: TimestampAsn.SignedData.encode(Buffer.from("xyz"))
			}

			respond({
				status: {status: "granted", statusString: ["Operation Okay"]},
				timeStampToken: token
			}, req)

			timestamp = yield timestamp
			timestamp.must.be.an.instanceof(TimestampResponse)
			timestamp.status.must.equal("granted")
			timestamp.token.must.eql(TimestampAsn.ContentInfo.encode(token))
		})

		it("must request with basic auth if given a password", function*() {
			Timestamp.read("http://foo:bar@example.com/tsa", DIGEST)

			var req = yield wait(this.mitm, "request")
			req.headers.host.must.equal("example.com")
			parseBasicAuth(req.headers.authorization).must.eql(["foo", "bar"])
			req.headers["content-type"].must.equal("application/timestamp-query")
			req.headers.accept.must.equal("application/timestamp-reply")
			req.method.must.equal("POST")
			req.url.must.equal("/tsa")
		})
	})

	describe("TimestampResponse", function() {
		it("must parse minimal response", function() {
			var token = {
				contentType: SIGNED_DATA_OID,
				content: TimestampAsn.SignedData.encode(Buffer.from("xyz"))
			}

			var res = new TimestampResponse(parse(serialize({
				status: {status: "granted"},
				timeStampToken: token
			})))

			res.status.must.equal("granted")
			res.must.have.property("message", null)
			res.token.must.eql(TimestampAsn.ContentInfo.encode(token))
		})

		it("must parse statusString", function() {
			var token = {
				contentType: SIGNED_DATA_OID,
				content: TimestampAsn.SignedData.encode(Buffer.from("xyz"))
			}

			var res = new TimestampResponse(parse(serialize({
				status: {
					status: "granted",
					statusString: ["Operation Okay", "Life is Good"]
				},

				timeStampToken: token
			})))

			res.status.must.equal("granted")
			res.message.must.equal("Operation Okay; Life is Good")
			res.token.must.eql(TimestampAsn.ContentInfo.encode(token))
		})
	})
})

function respond(timestamp, req) {
	req.res.setHeader("Content-Type", "application/timestamp-reply")
	req.res.end(TimestampResponseAsn.encode(timestamp))
}

function parseBasicAuth(line) {
	var auth = _.split2(line, " ")
	if (auth[0] != "Basic") return null
	return _.split2(_.parseBase64(auth[1]).toString(), ":")
}
