var Url = require("url")
var Crypto = require("crypto")
var SmartId = require("../../lib/smart_id")
var SmartIdError = require("../../lib/smart_id").SmartIdError
var SmartIdCertificate = require("../../lib/smart_id").SmartIdCertificate
var Certificate = require("../../lib/certificate")
var newCertificate = require("../fixtures").newCertificate
var wait = require("../../lib/promise").wait
var parseJson = require("../mitm").parseJson
var PARTY_NAME = "example.com"
var PARTY_UUID = "e7fd0962-6454-4333-a773-144a3aaa7f08"
var ID_NUMBER = "38706181337"
var CERTIFICATE = new Certificate(newCertificate())
var DOCUMENT_NUMBER = "PNOEE-" + ID_NUMBER + "-R2D2-Q"
var SESSION_ID = "f09c12d9-7e4c-4f9a-a7a7-bcffff1cd61c"

var smartId = new SmartId("http://example.com/smartid/", {
	user: PARTY_NAME,
	password: PARTY_UUID
})

var SMART_ID_ERRORS = [
	"TIMEOUT",
	"USER_REFUSED",
	"DOCUMENT_UNUSABLE",
	"WRONG_VC"
]

describe("SmartId", function() {
	require("../mitm")()

	function mustHandleErrors(request) {
		describe("as a Smart-Id method", function() {
			it("must resolve with null if session still running", function*() {
				var session = request()
				var req = yield wait(this.mitm, "request")
				respond({sessionID: SESSION_ID}, req)

				var res = smartId.wait(yield session)
				req = yield wait(this.mitm, "request")
				respond({state: "RUNNING"}, req)
				yield res.must.then.be.null()
			})

			it("must reject with SmartIdError given 400 Bad Request", function*() {
				var session = request({certificateLevel: "FOOBAR"})

				var req = yield wait(this.mitm, "request")
				req.res.statusCode = 400
				respond({code: 400, message: "Bad Request"}, req)

				var err
				try { yield session } catch (ex) { err = ex }
				err.must.be.an.error(SmartIdError)
				err.code.must.equal("BAD_REQUEST")
				err.message.must.equal("Bad Request")
				err.response.must.exist()
			})

			it("must reject with SmartIdError given 401 Unauthorized", function*() {
				var session = request()

				var req = yield wait(this.mitm, "request")
				req.res.statusCode = 401
				respond({code: 401, message: "Unauthorized"}, req)

				var err
				try { yield session } catch (ex) { err = ex }
				err.must.be.an.error(SmartIdError)
				err.code.must.equal("UNAUTHORIZED")
				err.message.must.equal("Unauthorized")
				err.response.must.exist()
			})

			it("must reject with SmartIdError given 403 Forbidden", function*() {
				var session = request({certificateLevel: "ADVANCED"})

				var req = yield wait(this.mitm, "request")
				req.res.statusCode = 403
				respond({code: 403, message: "Forbidden"}, req)

				var err
				try { yield session } catch (ex) { err = ex }
				err.must.be.an.error(SmartIdError)
				err.code.must.equal("FORBIDDEN")
				err.message.must.equal("Forbidden")
				err.response.must.exist()
			})

			it("must reject with SmartIdError given 404 Not Found", function*() {
				var session = request()

				var req = yield wait(this.mitm, "request")
				req.res.statusCode = 404
				respond({code: 404, message: "Not Found"}, req)

				var err
				try { yield session } catch (ex) { err = ex }
				err.must.be.an.error(SmartIdError)
				err.code.must.equal("ACCOUNT_NOT_FOUND")
				err.message.must.equal("Not Found")
				err.response.must.exist()
			})

			it("must reject with SmartIdError given 471 No Suitable Account",
				function*() {
				var session = request()

				var req = yield wait(this.mitm, "request")
				req.res.statusCode = 471
				respond({code: 471, message: "No suitable account found"}, req)

				var err
				try { yield session } catch (ex) { err = ex }
				err.must.be.an.error(SmartIdError)
				err.code.must.equal("NO_SUITABLE_CERTIFICATE")
				err.message.must.equal("No suitable account found")
				err.response.must.exist()
			})

			it("must reject with SmartIdError given 580 System Under Maintenance",
				function*() {
				var session = request()

				var req = yield wait(this.mitm, "request")
				req.res.statusCode = 580
				respond({code: 580, message: "System is under maintenance"}, req)

				var err
				try { yield session } catch (ex) { err = ex }
				err.must.be.an.error(SmartIdError)
				err.code.must.equal("MAINTENANCE")
				err.message.must.equal("System is under maintenance")
				err.response.must.exist()
			})

			SMART_ID_ERRORS.forEach(function(code) {
				it(`must reject with SmartIdError given ${code} error to session`,
					function*() {
					var session = request()

					var req = yield wait(this.mitm, "request")
					respond({sessionID: SESSION_ID}, req)

					var res = smartId.wait(yield session)
					req = yield wait(this.mitm, "request")
					respond({state: "COMPLETE", result: {endResult: code}}, req)

					var err
					try { yield res } catch (ex) { err = ex }
					err.must.be.an.error(SmartIdError)
					err.code.must.equal(code)
					err.message.must.not.equal(code)
					err.response.must.exist()
				})
			})
		})
	}

	describe(".prototype.certificate", function() {
		mustHandleErrors(smartId.certificate.bind(smartId, "PNOEE-" + ID_NUMBER))

		it("must resolve with a session that resolves with a certificate",
			function*() {
			var session = smartId.certificate("PNOEE-" + ID_NUMBER)

			var req = yield wait(this.mitm, "request")
			req.method.must.equal("POST")
			req.headers.host.must.equal("example.com")
			req.headers["content-type"].must.equal("application/json")
			req.headers.accept.must.equal("application/json")
			req.url.must.equal("/smartid/certificatechoice/etsi/PNOEE-" + ID_NUMBER)

			var body = yield parseJson(req)
			body.relyingPartyName.must.equal(PARTY_NAME)
			body.relyingPartyUUID.must.equal(PARTY_UUID)

			respond({sessionID: SESSION_ID}, req)

			var cert = smartId.wait(yield session, 10)
			req = yield wait(this.mitm, "request")
			req.method.must.equal("GET")
			req.headers.host.must.equal("example.com")
			req.headers.accept.must.equal("application/json")
			var url = Url.parse(req.url, true)
			url.pathname.must.equal("/smartid/session/" + SESSION_ID)
			url.query.timeoutMs.must.equal("10000")

			respond({
				state: "COMPLETE",
				result: {endResult: "OK", documentNumber: DOCUMENT_NUMBER},

				cert: {
					value: CERTIFICATE.toString("base64"),
					certificateLevel: "QUALIFIED"
				}
			}, req)

			cert = yield cert
			cert.must.be.an.instanceof(SmartIdCertificate)
			cert.serialNumber.must.eql(CERTIFICATE.serialNumber)
			cert.smartId.must.equal(DOCUMENT_NUMBER)
			cert.level.must.equal("QUALIFIED")
		})

		it("must query via document id given SmartIdCertificate", function*() {
			var cert = new SmartIdCertificate(newCertificate())
			cert.smartId = DOCUMENT_NUMBER
			smartId.certificate(cert)

			var req = yield wait(this.mitm, "request")
			req.method.must.equal("POST")
			req.headers.host.must.equal("example.com")
			req.url.must.equal("/smartid/certificatechoice/document/" + cert.smartId)
		})
	})

	describe(".prototype.authenticate", function() {
		mustHandleErrors(smartId.authenticate.bind(
			smartId,
			"PNOEE-" + ID_NUMBER,
			Crypto.randomBytes(32)
		))

		it("must resolve with a session that resolves with a certificate",
			function*() {
			var authableHash = Crypto.randomBytes(32)
			var session = smartId.authenticate("PNOEE-" + ID_NUMBER, authableHash)

			var req = yield wait(this.mitm, "request")
			req.method.must.equal("POST")
			req.headers.host.must.equal("example.com")
			req.headers["content-type"].must.equal("application/json")
			req.headers.accept.must.equal("application/json")
			req.url.must.equal("/smartid/authentication/etsi/PNOEE-" + ID_NUMBER)

			var body = yield parseJson(req)
			body.relyingPartyName.must.equal(PARTY_NAME)
			body.relyingPartyUUID.must.equal(PARTY_UUID)
			body.hash.must.equal(authableHash.toString("base64"))
			body.hashType.must.equal("SHA256")

			respond({sessionID: SESSION_ID}, req)

			var certAndSignature = smartId.wait(yield session, 10)
			req = yield wait(this.mitm, "request")
			req.method.must.equal("GET")
			req.headers.host.must.equal("example.com")
			req.headers.accept.must.equal("application/json")
			var url = Url.parse(req.url, true)
			url.pathname.must.equal("/smartid/session/" + SESSION_ID)
			url.query.timeoutMs.must.equal("10000")

			respond({
				state: "COMPLETE",
				result: {endResult: "OK", documentNumber: DOCUMENT_NUMBER},

				cert: {
					value: CERTIFICATE.toString("base64"),
					certificateLevel: "QUALIFIED"
				},

				signature: {
					algorithm: "sha256WithRSAEncryption",
					value: Buffer.from("coffee").toString("base64")
				}
			}, req)

			certAndSignature = yield certAndSignature
			certAndSignature[0].must.be.an.instanceof(SmartIdCertificate)
			certAndSignature[0].serialNumber.must.eql(CERTIFICATE.serialNumber)
			certAndSignature[0].smartId.must.equal(DOCUMENT_NUMBER)
			certAndSignature[0].level.must.equal("QUALIFIED")
			certAndSignature[1].must.eql(Buffer.from("coffee"))
		})

		it("must query via document id given SmartIdCertificate", function*() {
			var cert = new SmartIdCertificate(newCertificate())
			cert.smartId = DOCUMENT_NUMBER
			var authableHash = Crypto.randomBytes(32)
			smartId.authenticate(cert, authableHash)

			var req = yield wait(this.mitm, "request")
			req.method.must.equal("POST")
			req.headers.host.must.equal("example.com")
			req.url.must.equal("/smartid/authentication/document/" + cert.smartId)

			var body = yield parseJson(req)
			body.hash.must.equal(authableHash.toString("base64"))
		})
	})

	describe(".prototype.sign", function() {
		mustHandleErrors(smartId.sign.bind(
			smartId,
			"PNOEE-" + ID_NUMBER,
			Crypto.randomBytes(32)
		))

		it("must resolve with a session that resolves with a signature",
			function*() {
			var signableHash = Crypto.randomBytes(32)
			var session = smartId.sign("PNOEE-" + ID_NUMBER, signableHash)

			var req = yield wait(this.mitm, "request")
			req.method.must.equal("POST")
			req.headers.host.must.equal("example.com")
			req.headers["content-type"].must.equal("application/json")
			req.headers.accept.must.equal("application/json")
			req.url.must.equal("/smartid/signature/etsi/PNOEE-" + ID_NUMBER)

			var body = yield parseJson(req)
			body.relyingPartyName.must.equal(PARTY_NAME)
			body.relyingPartyUUID.must.equal(PARTY_UUID)
			body.hash.must.equal(signableHash.toString("base64"))
			body.hashType.must.equal("SHA256")

			respond({sessionID: SESSION_ID}, req)

			var certAndSignature = smartId.wait(yield session, 10)
			req = yield wait(this.mitm, "request")
			req.method.must.equal("GET")
			req.headers.host.must.equal("example.com")
			req.headers.accept.must.equal("application/json")
			var url = Url.parse(req.url, true)
			url.pathname.must.equal("/smartid/session/" + SESSION_ID)
			url.query.timeoutMs.must.equal("10000")

			respond({
				state: "COMPLETE",
				result: {endResult: "OK", documentNumber: DOCUMENT_NUMBER},

				cert: {
					value: CERTIFICATE.toString("base64"),
					certificateLevel: "QUALIFIED"
				},

				signature: {
					algorithm: "sha256WithRSAEncryption",
					value: Buffer.from("coffee").toString("base64")
				}
			}, req)

			certAndSignature = yield certAndSignature
			certAndSignature[0].must.be.an.instanceof(SmartIdCertificate)
			certAndSignature[0].serialNumber.must.eql(CERTIFICATE.serialNumber)
			certAndSignature[0].smartId.must.equal(DOCUMENT_NUMBER)
			certAndSignature[0].level.must.equal("QUALIFIED")
			certAndSignature[1].must.eql(Buffer.from("coffee"))
		})

		it("must query via document id given SmartIdCertificate", function*() {
			var cert = new SmartIdCertificate(newCertificate())
			cert.smartId = DOCUMENT_NUMBER
			var signableHash = Crypto.randomBytes(32)
			smartId.sign(cert, signableHash)

			var req = yield wait(this.mitm, "request")
			req.method.must.equal("POST")
			req.headers.host.must.equal("example.com")
			req.url.must.equal("/smartid/signature/document/" + cert.smartId)

			var body = yield parseJson(req)
			body.hash.must.equal(signableHash.toString("base64"))
		})
	})

	describe(".prototype.wait", function() {
		it("must reject with SmartIdError if session not found", function*() {
			var session = smartId.certificate("PNOEE-" + ID_NUMBER)

			var req = yield wait(this.mitm, "request")
			req.url.must.equal("/smartid/certificatechoice/etsi/PNOEE-" + ID_NUMBER)
			respond({sessionID: SESSION_ID}, req)

			var res = smartId.wait(yield session, 10)
			req = yield wait(this.mitm, "request")
			req.res.statusCode = 404
			respond({code: 404, message: "Not Found"}, req)

			var err
			try { yield res } catch (ex) { err = ex }
			err.must.be.an.error(SmartIdError)
			err.code.must.equal("SESSION_NOT_FOUND")
			err.message.must.equal("Not Found")
			err.response.must.exist()
		})
	})

	describe(".verification", function() {
		it("must calculate verification code from hash", function() {
			SmartId.verification(Buffer.from(
				"78225701eab0c124a4909e28a7e3323f48c9e0de828f690763bcc57ac06de0e1",
				"hex"
			)).must.equal(2931)
		})
	})
})

function respond(obj, req) {
	req.res.setHeader("Content-Type", "application/json")
	req.res.end(JSON.stringify(obj))
}
