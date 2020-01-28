var _ = require("../lib/underscore")
var Neodoc = require("neodoc")
var SmartId = require("../lib/smart_id")
var SmartIdError = require("../lib/smart_id").SmartIdError
var Crypto = require("crypto")
var co = require("co")
var stringifyCertificate = require("./certificate_cli").stringify

var USAGE_TEXT = `
Usage: hades smart-id-certificate (-h | --help)
       hades smart-id-certificate [options] <country> <personal-id>

Options:
    -h, --help             Display this help and exit.
    -f, --format=FMT       Format to print the certificate in. [default: text]
    -t, --type=TYPE        Whether to get the sign or auth cert. [default: sign]
		-l, --level=LEVEL      Certificate security level. [default: qualified]
    --smart-id-user=NAME   Username (relying party name) for Smart-Id.
    --smart-id-password=UUID  Password (relying party UUID) for Smart-Id.

Formats:
    text                  Print human-readable information.
    pem                   Print the certificate only in PEM.

Certificate Types:
    auth                  Authentication certificate returned after PIN1.
    sign                  Signature certificate.

Certificate Levels:
		qscd
    qualified
		advanced
`.trimLeft()

module.exports = _.compose(errorify, co.wrap(function*(argv) {
	var args = Neodoc.run(USAGE_TEXT, {argv: argv})
	if (args["--help"]) return void process.stdout.write(USAGE_TEXT)

	var country = args["<country>"]
	var personalId = args["<personal-id>"]
	if (country == null) return void process.stdout.write(USAGE_TEXT)

	var smartId = args["--smart-id-user"] ? new SmartId({
		user: args["--smart-id-user"],
		password:  args["--smart-id-password"]
	}) : SmartId.demo

	var cert
	var type = args["--type"]
	var level = args["--level"].toUpperCase()
	var semanticId = `PNO${country}-${personalId}`

	switch (type) {
		case "auth":
			var authableHash = Crypto.randomBytes(32)

			var authSession = yield smartId.authenticate(semanticId, authableHash, {
				certificateLevel: level
			})

			console.warn("Verification code: " + serializeVerification(authableHash))

			var _signature
			;[cert, _signature] = yield smartId.wait(authSession)
			break

		case "sign":
			var certSession = yield smartId.certificate(semanticId, {
				certificateLevel: args["--level"].toUpperCase()
			})

			cert = yield smartId.wait(certSession)
			break
	}

	var fmt = args["--format"]
	switch (fmt.toLowerCase()) {
		case "text":
			console.log(stringifyCertificate(cert))
			console.log()
			console.log("Smart-Id Document Number: %s", cert.smartId)
			console.log("Smart-Id Certificate Level: %s", cert.level)
			break

		case "pem": console.log(cert.toString("pem")); break
		default: throw new RangeError("Unsupported format: " + fmt)
	}
}))

function errorify(res) {
	return res.catch(function(err) {
		if (err instanceof SmartIdError) {
			process.exitCode = 3
			console.error("Smart-Id Error: %s: %s", err.code, err.message)
		}
		else throw err
	})
}

function serializeVerification(signableHash) {
	return ("000" + SmartId.verification(signableHash)).slice(-4)
}
