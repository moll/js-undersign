var _ = require("../lib/underscore")
var Fs = require("fs")
var Mime = require("mime")
var Tsl = require("../lib/tsl")
var Xades = require("../xades")
var Neodoc = require("neodoc")
var SmartId = require("../lib/smart_id")
var SmartIdError = require("../lib/smart_id").SmartIdError
var Certificate = require("../lib/certificate")
var Ocsp = require("../lib/ocsp")
var Timestamp = require("../lib/timestamp")
var digest = require("../lib/x509_asn").digest
var co = require("co")
var sha256 = require("../lib/crypto").hash.bind(null, "sha256")
var sha256Stream = require("../lib/crypto").hashStream.bind(null, "sha256")

var USAGE_TEXT = `
Usage: hades smart-id-sign (-h | --help)
       hades smart-id-sign [options] <file>

Options:
    -h, --help                 Display this help and exit.
    -c, --country=XX           Country of person. [default: EE]
    -i, --id=X                 Personal id number.
  	--tsl=FILE                 Use given Trust Service List.
    --issuer=PATH              Explicit issuer certificate if TSL unavailable.
    --ocsp-url=URL             URL for the OCSP server.
    --smart-id-url=URL        Custom URL for Smart-Id API.
  	--smart-id-user=NAME       Username (relying party name) for Smart Id.
  	--smart-id-password=UUID   Password (relying party UUID) for Smart Id.
  	--timemark                 Get the Estonian BDOC's timemark with OCSP.
  	--timestamp                Get a timestamp on the signature.
    --timestamp-url=URL        URL for the timestamp server.
`.trimLeft()

module.exports = _.compose(errorify, co.wrap(function*(argv) {
	var args = Neodoc.run(USAGE_TEXT, {argv: argv})
	if (args["--help"]) return void process.stdout.write(USAGE_TEXT)
	var path = args["<file>"]
	if (path == null) return void process.stdout.write(USAGE_TEXT)

	var smartId = args["--smart-id-url"] || args["--smart-id-user"]
		? new SmartId(args["--smart-id-url"], {
			user: args["--smart-id-user"],
			password:  args["--smart-id-password"]
		})
		: SmartId.demo

	var country = args["--country"]
	var personalId = args["--id"]
	var semanticId = `PNO${country}-${personalId}`

	var tslPath = args["--tsl"]
	var issuerPath = args["--issuer"]

	if (!(tslPath || issuerPath))
		throw new Error("Pass either --tsl or <issuer-certificate>")

	var cert = yield smartId.wait(yield smartId.certificate(semanticId))
	var tsl = tslPath && Tsl.parse(Fs.readFileSync(tslPath))
	var issuer = issuerPath && Certificate.parse(Fs.readFileSync(issuerPath))
	if (issuer == null) issuer = tsl.certificates.getIssuer(cert)

	if (issuer == null) throw new Error(
		"Can't find issuer: " + cert.issuerDistinguishedName.join(", ")
	)

	var xades = new Xades(cert, [{
		path: path,
		type: Mime.lookup(path),
		hash: yield sha256Stream(Fs.createReadStream(path))
	}], {policy: args["--timemark"] ? "bdoc" : null})

	console.warn(
		"Confirmation code: " + serializeConfirmation(xades.signableHash)
	)

	var [_cert, signature] = yield smartId.wait(
		yield smartId.sign(cert, xades.signableHash)
	)

	xades.setSignature(signature)

	if (args["--timestamp"]) xades.setTimestamp(yield Timestamp.request(
		args["--timestamp-url"],
		sha256(xades.signatureElement)
	).then(Timestamp.parse))

	xades.setOcspResponse(yield Ocsp.request(issuer, cert, {
		url: args["--ocsp-url"],

		nonce: args["--timemark"]
			? digest("sha1", Buffer.from(signature, "base64"))
			: null
	}).then(Ocsp.parse))

	console.log(xades.toString())
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

function serializeConfirmation(signableHash) {
	return ("000" + SmartId.verification(signableHash)).slice(-4)
}
