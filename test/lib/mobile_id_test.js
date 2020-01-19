var _ = require("../../lib/underscore")
var Url = require("url")
var MobileId = require("../../lib/mobile_id")
var MobileIdError = require("../../lib/mobile_id").MobileIdError
var Certificate = require("../../lib/certificate")
var newCertificate = require("../fixtures").newCertificate
var wait = require("../../lib/promise").wait
var parseJson = require("../mitm").parseJson
var jsonify = _.compose(JSON.parse, JSON.stringify)
var PHONE_NUMBER = "+3725031337"
var ID_NUMBER = "38706181337"
var PARTY_NAME = "example.com"
var PARTY_UUID = "e7fd0962-6454-4333-a773-144a3aaa7f08"
var SESSION_ID = "f09c12d9-7e4c-4f9a-a7a7-bcffff1cd61c"
var CERTIFICATE = new Certificate(newCertificate())
var EMPTY_BUFFER = Buffer.alloc(0)

var mobileId = new MobileId("http://example.com/mid/", {
	user: PARTY_NAME,
	password: PARTY_UUID
})

var MOBILE_ID_ERRORS = [
	"TIMEOUT",
	"NOT_MID_CLIENT",
	"USER_CANCELLED",
	"SIGNATURE_HASH_MISMATCH",
	"PHONE_ABSENT",
	"DELIVERY_ERROR",
	"SIM_ERROR"
]

describe("MobileId", function() {
	require("../mitm")()

	describe(".prototype.readCertificate", function() {
		it("must resolve with a certificate", function*() {
			var cert = mobileId.readCertificate(PHONE_NUMBER, ID_NUMBER)

			var req = yield wait(this.mitm, "request")
			req.method.must.equal("POST")
			req.headers.host.must.equal("example.com")
			req.headers["content-type"].must.equal("application/json")
			req.headers.accept.must.equal("application/json")
			req.url.must.equal("/mid/certificate")

			var body = yield parseJson(req)
			body.relyingPartyName.must.equal(PARTY_NAME)
			body.relyingPartyUUID.must.equal(PARTY_UUID)
			body.phoneNumber.must.equal(PHONE_NUMBER)
			body.nationalIdentityNumber.must.equal(ID_NUMBER)

			respond({result: "OK", cert: CERTIFICATE.toString("base64")}, req)

			cert = yield cert
			cert.must.be.an.instanceof(Certificate)
			cert.serialNumber.must.eql(CERTIFICATE.serialNumber)
		})

		;["NOT_FOUND", "NOT_ACTIVE"].forEach(function(code) {
			it(`must reject with MobileIdError given ${code} error`, function*() {
				var cert = mobileId.readCertificate(PHONE_NUMBER, ID_NUMBER)

				var req = yield wait(this.mitm, "request")
				respond({result: code}, req)

				var err
				try { yield cert } catch (ex) { err = ex }
				err.must.be.an.error(MobileIdError)
				err.code.must.equal(code)
			})
		})

		it("must reject with MobileIdError given 400 Bad Request", function*() {
			var cert = mobileId.readCertificate(PHONE_NUMBER, "387061869")

			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 400
			respond({error: "nationalIdentityNumber must contain of 11 digits"}, req)

			var err
			try { yield cert } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("BAD_REQUEST")
		})

		it("must reject with MobileIdError given 401 Unauthorized", function*() {
			var cert = mobileId.readCertificate(PHONE_NUMBER, "387061869")

			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 401
			respond({error: "Failed to authorize user"}, req)

			var err
			try { yield cert } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("UNAUTHORIZED")
		})
	})

	describe(".prototype.authenticate", function() {
		it("must respond with session id", function*() {
			var authableHash = Buffer.from("deadbeef")
			var sessionId = mobileId.authenticate(
				PHONE_NUMBER,
				ID_NUMBER,
				authableHash
			)

			var req = yield wait(this.mitm, "request")
			req.method.must.equal("POST")
			req.headers.host.must.equal("example.com")
			req.headers["content-type"].must.equal("application/json")
			req.headers.accept.must.equal("application/json")
			req.url.must.equal("/mid/authentication")

			var body = yield parseJson(req)
			body.relyingPartyName.must.equal(PARTY_NAME)
			body.relyingPartyUUID.must.equal(PARTY_UUID)
			body.phoneNumber.must.equal(PHONE_NUMBER)
			body.nationalIdentityNumber.must.equal(ID_NUMBER)
			body.hash.must.equal(authableHash.toString("base64"))
			body.hashType.must.equal("SHA256")
			body.language.must.equal("EST")

			respond({sessionID: SESSION_ID}, req)

			yield sessionId.must.then.equal(SESSION_ID)
		})

		it("must reject with MobileIdError given 400 Bad Request", function*() {
			var res = mobileId.authenticate(PHONE_NUMBER, ID_NUMBER, EMPTY_BUFFER, {
				language: "FOO"
			})

			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 400
			respond({error: "Unknown language 'FOO'"}, req)

			var err
			try { yield res } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("BAD_REQUEST")
		})

		it("must reject with MobileIdError given 401 Unauthorized", function*() {
			var res = mobileId.authenticate(PHONE_NUMBER, ID_NUMBER, EMPTY_BUFFER)
			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 401
			respond({error: "Failed to authorize user"}, req)

			var err
			try { yield res } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("UNAUTHORIZED")
		})
	})

	describe(".prototype.sign", function() {
		it("must respond with session id", function*() {
			var signableHash = Buffer.from("deadbeef")
			var sessionId = mobileId.sign(PHONE_NUMBER, ID_NUMBER, signableHash)

			var req = yield wait(this.mitm, "request")
			req.method.must.equal("POST")
			req.headers.host.must.equal("example.com")
			req.headers["content-type"].must.equal("application/json")
			req.headers.accept.must.equal("application/json")
			req.url.must.equal("/mid/signature")

			var body = yield parseJson(req)
			body.relyingPartyName.must.equal(PARTY_NAME)
			body.relyingPartyUUID.must.equal(PARTY_UUID)
			body.phoneNumber.must.equal(PHONE_NUMBER)
			body.nationalIdentityNumber.must.equal(ID_NUMBER)
			body.hash.must.equal(signableHash.toString("base64"))
			body.hashType.must.equal("SHA256")
			body.language.must.equal("EST")

			respond({sessionID: SESSION_ID}, req)

			yield sessionId.must.then.equal(SESSION_ID)
		})

		it("must reject with MobileIdError given 400 Bad Request", function*() {
			var res = mobileId.sign(PHONE_NUMBER, ID_NUMBER, EMPTY_BUFFER, {
				language: "FOO"
			})

			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 400
			respond({error: "Unknown language 'FOO'"}, req)

			var err
			try { yield res } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("BAD_REQUEST")
		})

		it("must reject with MobileIdError given 401 Unauthorized", function*() {
			var res = mobileId.sign(PHONE_NUMBER, ID_NUMBER, EMPTY_BUFFER)

			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 401
			respond({error: "Failed to authorize user"}, req)

			var err
			try { yield res } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("UNAUTHORIZED")
		})
	})

	describe(".prototype.waitForAuthentication", function() {
		it("must return certificate and signature", function*() {
			var res = mobileId.waitForAuthentication(SESSION_ID, 10)
			
			var req = yield wait(this.mitm, "request")
			req.method.must.equal("GET")
			req.headers.host.must.equal("example.com")
			req.headers.accept.must.equal("application/json")
			var url = Url.parse(req.url, true)
			url.pathname.must.equal("/mid/authentication/session/" + SESSION_ID)
			url.query.timeoutMs.must.equal("10000")

			respond({
				result: "OK",
				state: "COMPLETE",

				cert: CERTIFICATE.toString("base64"),

				signature: {
					algorithm: "sha256WithRSAEncryption",
					value: Buffer.from("coffee").toString("base64")
				}
			}, req)

			var [cert, signature] = yield res
			cert.must.be.an.instanceof(Certificate)
			cert.serialNumber.must.eql(CERTIFICATE.serialNumber)
			signature.must.eql(Buffer.from("coffee"))
		})

		it("must return null if still running", function*() {
			var signature = mobileId.waitForAuthentication(SESSION_ID, 10)
			var req = yield wait(this.mitm, "request")
			respond({state: "RUNNING"}, req)
			yield signature.must.then.be.null()
		})

		MOBILE_ID_ERRORS.forEach(function(code) {
			it(`must reject with MobileIdError given ${code} error`, function*() {
				var signature = mobileId.waitForAuthentication(SESSION_ID)

				var req = yield wait(this.mitm, "request")
				req.res.setHeader("Content-Type", "application/json")
				req.res.end(JSON.stringify({state: "COMPLETE", result: code}))

				var err
				try { yield signature } catch (ex) { err = ex }
				err.must.be.an.error(MobileIdError)
				err.code.must.equal(code)
			})
		})

		it("must reject with MobileIdError given 400 Bad Request", function*() {
			var cert = mobileId.waitForAuthentication("foo")

			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 400
			respond({error: "Invalid format for sessionId='foo'"}, req)

			var err
			try { yield cert } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("BAD_REQUEST")
		})

		it("must reject with MobileIdError given 401 Unauthorized", function*() {
			var cert = mobileId.waitForAuthentication(SESSION_ID)

			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 401
			respond({error: "Failed to authorize user"}, req)

			var err
			try { yield cert } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("UNAUTHORIZED")
		})
	})

	describe(".prototype.waitForSignature", function() {
		it("must return signature", function*() {
			var signature = mobileId.waitForSignature(SESSION_ID, 10)
			
			var req = yield wait(this.mitm, "request")
			req.method.must.equal("GET")
			req.headers.host.must.equal("example.com")
			req.headers.accept.must.equal("application/json")
			var url = Url.parse(req.url, true)
			url.pathname.must.equal("/mid/signature/session/" + SESSION_ID)
			url.query.timeoutMs.must.equal("10000")

			respond({
				result: "OK",
				state: "COMPLETE",

				signature: {
					algorithm: "sha256WithRSAEncryption",
					value: Buffer.from("coffee").toString("base64")
				}
			}, req)

			yield signature.must.then.eql(Buffer.from("coffee"))
		})

		it("must return null if still running", function*() {
			var signature = mobileId.waitForSignature(SESSION_ID, 10)
			var req = yield wait(this.mitm, "request")
			respond({state: "RUNNING"}, req)
			yield signature.must.then.be.null()
		})

		MOBILE_ID_ERRORS.forEach(function(code) {
			it(`must reject with MobileIdError given ${code} error`, function*() {
				var signature = mobileId.waitForSignature(SESSION_ID)

				var req = yield wait(this.mitm, "request")
				req.res.setHeader("Content-Type", "application/json")
				req.res.end(JSON.stringify({state: "COMPLETE", result: code}))

				var err
				try { yield signature } catch (ex) { err = ex }
				err.must.be.an.error(MobileIdError)
				err.code.must.equal(code)
			})
		})

		it("must reject with MobileIdError given 400 Bad Request", function*() {
			var cert = mobileId.waitForSignature("foo")

			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 400
			respond({error: "Invalid format for sessionId='foo'"}, req)

			var err
			try { yield cert } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("BAD_REQUEST")
		})

		it("must reject with MobileIdError given 401 Unauthorized", function*() {
			var cert = mobileId.waitForSignature(SESSION_ID)

			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 401
			respond({error: "Failed to authorize user"}, req)

			var err
			try { yield cert } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("UNAUTHORIZED")
		})
	})

	describe(".confirmation", function() {
		it("must calculate confirmation from hash", function() {
			MobileId.confirmation(Buffer.from(
				"78225701eab0c124a4909e28a7e3323f48c9e0de828f690763bcc57ac06de0e1",
				"hex"
			)).must.equal(3937)
		})
	})

	describe("MobileIdError", function() {
		describe(".prototype.toJSON", function() {
			// This will be handy when storing the error in the database for
			// asynchronous status querying.
			it("must serialize with name, code and message", function() {
				var msg = "Person did not respond in time"
				var err = new MobileIdError("TIMEOUT", msg, {response: {body: "foo"}})

				jsonify(err).must.eql({
					name: "MobileIdError",
					code: "TIMEOUT",
					message: msg
				})
			})
		})
	})
})

function respond(obj, req) {
	req.res.setHeader("Content-Type", "application/json")
	req.res.end(JSON.stringify(obj))
}
