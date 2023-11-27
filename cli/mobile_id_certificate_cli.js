var _ = require("../lib/underscore")
var Neodoc = require("neodoc")
var MobileId = require("../lib/mobile_id")
var MobileIdError = require("../lib/mobile_id").MobileIdError
var Crypto = require("crypto")
var co = require("co")
var stringifyCertificate = require("./certificate_cli").stringify

var USAGE_TEXT = `
Usage: hades mobile-id-certificate (-h | --help)
       hades mobile-id-certificate [options] <phone-number> <personal-id-number>

Options:
    -h, --help             Display this help and exit.
    -f, --format=FMT       Format to print the certificate in. [default: text]
    -t, --type=TYPE        Whether to get the sign or auth cert. [default: sign]
    --mobile-id-url=URL    Custom URL for Mobile-Id API.
    --mobile-id-user=NAME  Username (relying party name) for Mobile-Id.
    --mobile-id-password=UUID  Password (relying party UUID) for Mobile-Id.

Formats:
    text                  Print human-readable information.
    pem                   Print the certificate only in PEM.

Certificate Types:
    auth                  Authentication certificate returned after PIN1.
    sign                  Signature certificate.

Note that the getting the authentication certificate triggers authentication,
which isn't something you can do without the person knowing.
`.trimLeft()

module.exports = _.compose(errorify, co.wrap(function*(argv) {
	var args = Neodoc.run(USAGE_TEXT, {argv: argv})
	if (args["--help"]) return void process.stdout.write(USAGE_TEXT)

	var phoneNumber = args["<phone-number>"]
	var personalId = args["<personal-id-number>"]
	if (phoneNumber == null) return void process.stdout.write(USAGE_TEXT)

	var mobileId = args["--mobile-id-user"] || args["--mobile-id-url"]
		? new MobileId(args["--mobile-id-url"], {
			user: args["--mobile-id-user"],
			password:  args["--mobile-id-password"]
		})
		: MobileId.demo

	var cert
	var type = args["--type"]

	switch (type) {
		case "auth":
			var authableHash = Crypto.randomBytes(32)
			console.warn("Confirmation code: " + serializeConfirmation(authableHash))

			var session = yield mobileId.authenticate(
				phoneNumber,
				personalId,
				authableHash
			)

			var _signature
			;[cert, _signature] = yield mobileId.wait(session)
			break

		case "sign":
			cert = yield mobileId.certificate(phoneNumber, personalId)
			break

		default: throw new RangeError("Unsupported certiifcate type: " + type)
	}

	var fmt = args["--format"]
	switch (fmt.toLowerCase()) {
		case "text": console.log(stringifyCertificate(cert)); break
		case "pem": console.log(cert.toString("pem")); break
		default: throw new RangeError("Unsupported format: " + fmt)
	}
}))

function errorify(res) {
	return res.catch(function(err) {
		if (err instanceof MobileIdError) {
			process.exitCode = 3
			console.error("Mobile-Id Error: " + err.message)
		}
		else throw err
	})
}

function serializeConfirmation(signableHash) {
	return ("000" + MobileId.verification(signableHash)).slice(-4)
}
