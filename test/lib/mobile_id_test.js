var _ = require("../../lib/underscore")
var Url = require("url")
var Crypto = require("crypto")
var MobileId = require("../../lib/mobile_id")
var MobileIdError = require("../../lib/mobile_id").MobileIdError
var MobileIdSession = require("../../lib/mobile_id").MobileIdSession
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

	describe(".prototype.certificate", function() {
		it("must resolve with a certificate", function*() {
			var cert = mobileId.certificate(PHONE_NUMBER, ID_NUMBER)

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

		it("must reject with MobileIdError given NOT_FOUND error", function*() {
			var cert = mobileId.certificate(PHONE_NUMBER, ID_NUMBER)
			var req = yield wait(this.mitm, "request")
			respond({result: "NOT_FOUND"}, req)

			var err
			try { yield cert } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("NOT_FOUND")
			err.response.must.exist()
		})

		it("must reject with MobileIdError given 400 Bad Request", function*() {
			var cert = mobileId.certificate(PHONE_NUMBER, "387061869")
			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 400
			respond({error: "nationalIdentityNumber must contain of 11 digits"}, req)

			var err
			try { yield cert } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("BAD_REQUEST")
			err.message.must.equal("nationalIdentityNumber must contain of 11 digits")
			err.response.must.exist()
		})

		it("must reject with MobileIdError given 401 Unauthorized", function*() {
			var cert = mobileId.certificate(PHONE_NUMBER, "387061869")
			var req = yield wait(this.mitm, "request")
			req.res.statusCode = 401
			respond({error: "Failed to authorize user"}, req)

			var err
			try { yield cert } catch (ex) { err = ex }
			err.must.be.an.error(MobileIdError)
			err.code.must.equal("UNAUTHORIZED")
			err.message.must.equal("Failed to authorize user")
			err.response.must.exist()
		})
	})

	function mustHandleErrors(request) {
		describe("as a Mobile-Id method", function() {
			it("must resolve with null if session still running", function*() {
				var session = request()
				var req = yield wait(this.mitm, "request")
				respond({sessionID: SESSION_ID}, req)

				var res = mobileId.wait(yield session)
				req = yield wait(this.mitm, "request")
				respond({state: "RUNNING"}, req)
				yield res.must.then.be.null()
			})

			it("must reject with MobileIdError given 400 Bad Request", function*() {
				var session = request({language: "FOO"})
				var req = yield wait(this.mitm, "request")
				req.res.statusCode = 400
				respond({error: "Unknown language 'FOO'"}, req)

				var err
				try { yield session } catch (ex) { err = ex }
				err.must.be.an.error(MobileIdError)
				err.code.must.equal("BAD_REQUEST")
				err.message.must.equal("Unknown language 'FOO'")
				err.response.must.exist()
			})

			it("must reject with MobileIdError given 401 Unauthorized", function*() {
				var session = request()
				var req = yield wait(this.mitm, "request")
				req.res.statusCode = 401
				respond({error: "Failed to authorize user"}, req)

				var err
				try { yield session } catch (ex) { err = ex }
				err.must.be.an.error(MobileIdError)
				err.code.must.equal("UNAUTHORIZED")
				err.message.must.equal("Failed to authorize user")
				err.response.must.exist()
			})

			it("must reject with MobileIdError given 400 Bad Request to session",
				function*() {
				var session = request()
				var req = yield wait(this.mitm, "request")
				respond({sessionID: SESSION_ID}, req)

				var res = mobileId.wait(yield session)
				req = yield wait(this.mitm, "request")
				req.res.statusCode = 400
				respond({error: "Invalid format for sessionId='foo'"}, req)

				var err
				try { yield res } catch (ex) { err = ex }
				err.must.be.an.error(MobileIdError)
				err.code.must.equal("BAD_REQUEST")
				err.message.must.equal("Invalid format for sessionId='foo'")
				err.response.must.exist()
			})

			it("must reject with MobileIdError given 401 Unauthorized to session",
				function*() {
				var session = request()
				var req = yield wait(this.mitm, "request")
				respond({sessionID: SESSION_ID}, req)

				var res = mobileId.wait(yield session)
				req = yield wait(this.mitm, "request")
				req.res.statusCode = 401
				respond({error: "Failed to authorize user"}, req)

				var err
				try { yield res } catch (ex) { err = ex }
				err.must.be.an.error(MobileIdError)
				err.code.must.equal("UNAUTHORIZED")
				err.message.must.equal("Failed to authorize user")
				err.response.must.exist()
			})

			MOBILE_ID_ERRORS.forEach(function(code) {
				it(`must reject with MobileIdError given ${code} error to session`,
					function*() {
					var session = request()
					var req = yield wait(this.mitm, "request")
					respond({sessionID: SESSION_ID}, req)

					var res = mobileId.wait(yield session)
					req = yield wait(this.mitm, "request")
					respond({state: "COMPLETE", result: code}, req)

					var err
					try { yield res } catch (ex) { err = ex }
					err.must.be.an.error(MobileIdError)
					err.code.must.equal(code)
					err.message.must.not.equal(code)
					err.response.must.exist()
				})
			})
		})
	}

	describe(".prototype.authenticate", function() {
		mustHandleErrors(mobileId.authenticate.bind(
			mobileId,
			PHONE_NUMBER,
			ID_NUMBER,
			Crypto.randomBytes(32)
		))

		it("must resolve with a session that resolves with an authentication",
			function*() {
			var authableHash = Crypto.randomBytes(32)
			var session = mobileId.authenticate(
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

			var res = mobileId.wait(yield session, 10)

			req = yield wait(this.mitm, "request")
			req.method.must.equal("GET")
			req.headers.host.must.equal("example.com")
			req.headers.accept.must.equal("application/json")
			var url = Url.parse(req.url, true)
			url.pathname.must.equal("/mid/authentication/session/" + SESSION_ID)
			url.query.timeoutMs.must.equal("10000")

			respond({
				state: "COMPLETE",
				result: "OK",

				cert: CERTIFICATE.toString("base64"),

				signature: {
					algorithm: "sha256WithRSAEncryption",
					value: Buffer.from("coffee").toString("base64")
				}
			}, req)

			var certAndSignature = yield res
			certAndSignature[0].must.be.an.instanceof(Certificate)
			certAndSignature[0].serialNumber.must.eql(CERTIFICATE.serialNumber)
			certAndSignature[1].must.eql(Buffer.from("coffee"))
		})
	})

	describe(".prototype.sign", function() {
		mustHandleErrors(mobileId.sign.bind(
			mobileId,
			PHONE_NUMBER,
			ID_NUMBER,
			Crypto.randomBytes(32)
		))

		it("must resolve with a session that resolves with a signature",
			function*() {
			var signableHash = Crypto.randomBytes(32)
			var session = mobileId.sign(PHONE_NUMBER, ID_NUMBER, signableHash)

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

			var signature = mobileId.wait(yield session, 10)

			req = yield wait(this.mitm, "request")
			req.method.must.equal("GET")
			req.headers.host.must.equal("example.com")
			req.headers.accept.must.equal("application/json")
			var url = Url.parse(req.url, true)
			url.pathname.must.equal("/mid/signature/session/" + SESSION_ID)
			url.query.timeoutMs.must.equal("10000")

			respond({
				state: "COMPLETE",
				result: "OK",

				signature: {
					algorithm: "sha256WithRSAEncryption",
					value: Buffer.from("coffee").toString("base64")
				}
			}, req)

			yield signature.must.then.eql(Buffer.from("coffee"))
		})
	})

	describe(".verification", function() {
		it("must calculate verification code from hash", function() {
			MobileId.verification(Buffer.from(
				"78225701eab0c124a4909e28a7e3323f48c9e0de828f690763bcc57ac06de0e1",
				"hex"
			)).must.equal(3937)
		})
	})

	describe("MobileIdSession", function() {
		describe(".prototype.toJSON", function() {
			;["auth", "sign"].forEach(function(type) {
				it("must serialize a " + type + " session", function() {
					new MobileIdSession(type, SESSION_ID).toJSON().must.eql({
						type: type,
						id: SESSION_ID
					})
				})
			})
		})

		describe(".parse", function() {
			;["auth", "sign"].forEach(function(type) {
				it("must parse a " + type + " session back", function() {
					var session = new MobileIdSession(type, SESSION_ID)
					MobileIdSession.parse(session.toJSON()).must.eql(session)
				})
			})
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
