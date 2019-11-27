var Fs = require("fs")
var Neodoc = require("neodoc")
var Certificate = require("../lib/certificate")
var Tsl = require("../lib/tsl")
var outdent = require("../lib/outdent")
var slurp = require("../lib/stream").slurp
var sha1 = require("../lib/crypto").hash.bind(null, "sha1")
var co = require("co")

var USAGE_TEXT = `
Usage: hades certificate (-h | --help)
       hades certificate [options] [<certificate-file>|-]

Options:
    -h, --help           Display this help and exit.
    --tsl=FILE           Use given Trust Service List.
    --issuer=PATH        Issuer certificate.
    --validate           Validate issuer's signature.
`.trimLeft()

exports = module.exports = co.wrap(function*(argv) {
	var args = Neodoc.run(USAGE_TEXT, {argv: argv})
	if (args["--help"]) return void process.stdout.write(USAGE_TEXT)

	var certPath
	if (args["-"]) certPath = "-"
	else if ("<certificate-file>" in args) certPath = args["<certificate-file>"]
	if (certPath == null) return void process.stdout.write(USAGE_TEXT)

	var stream = certPath == "-" ? process.stdin : Fs.createReadStream(certPath)
	var cert = Certificate.parse(yield slurp(stream))
	console.log(stringify(cert))

	if (args["--validate"]) {
		var tslPath = args["--tsl"]
		var tsl = tslPath && Tsl.parse(Fs.readFileSync(tslPath))
		var issuerPath = args["--issuer"]

		if (!(tslPath || issuerPath))
			throw new Error("Pass either --tsl or <issuer-certificate>")

		var issuer = issuerPath && Certificate.parse(Fs.readFileSync(issuerPath))
		if (issuer == null) issuer = tsl.certificates.getIssuer(cert)

		if (issuer == null) throw new Error(
			"Can't find issuer: " + cert.issuerDistinguishedName.join(", ")
		)

		if (issuer.hasIssued(cert)) console.log("Issuer Signature: OK")
		else {
			console.log("Issuer Signature: Invalid")
			process.exitCode = 1
		}
	}
})

exports.stringify = stringify

function stringify(certificate) {
	return outdent`
		Subject Name: ${certificate.subjectDistinguishedName.join(", ")}
		Subject SHA1: ${sha1(certificate.subjectDer).toString("hex")}
		Serial Number: ${certificate.serialNumber.toString()}
		Serial Number (Hex): ${certificate.serialNumber.toString(16)}
		Public Key Algorithm: ${(
			certificate.publicKeyAlgorithmName ||
			certificate.publicKeyAlgorithm
		).toUpperCase()}
		Public Key Parameters: ${stringifyPublicKeyParams(certificate)}
		Valid From: ${certificate.validFrom.toISOString()}
		Valid Until: ${certificate.validUntil.toISOString()}
		OCSP URL: ${certificate.ocspUrl || "none"}

		Issuer Name: ${certificate.issuerDistinguishedName.join(", ")}
		Issuer Signature Algorithm: ${(
			certificate.issuerSignatureAlgorithmName ||
			certificate.issuerSignatureAlgorithm
		).toUpperCase()}
	`
}

function stringifyPublicKeyParams(certificate) {
	switch (certificate.publicKeyAlgorithmName) {
		case "ecdsa":
			var params = certificate.publicKeyParameters
			if (params.type == "namedCurve") return params.value
			// Fall through.

		default: return "Unknown"
	}
}
