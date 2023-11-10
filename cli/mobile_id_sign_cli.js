var _ = require("../lib/underscore")
var Fs = require("fs")
var Mime = require("mime")
var Tsl = require("../lib/tsl")
var Xades = require("../xades")
var Neodoc = require("neodoc")
var MobileId = require("../lib/mobile_id")
var MobileIdError = require("../lib/mobile_id").MobileIdError
var Certificate = require("../lib/certificate")
var Ocsp = require("../lib/ocsp")
var Timestamp = require("../lib/timestamp")
var digest = require("../lib/x509_asn").digest
var co = require("co")
var sha256 = require("../lib/crypto").hash.bind(null, "sha256")
var sha256Stream = require("../lib/crypto").hashStream.bind(null, "sha256")

var USAGE_TEXT = `
Usage: hades mobile-id-sign (-h | --help)
       hades mobile-id-sign [options] <file>

Options:
    -h, --help                 Display this help and exit.
    -p, --phone=X              Phone number.
    -i, --id=X                 Personal id number.
  	--tsl=FILE                 Use given Trust Service List.
    --issuer=PATH              Explicit issuer certificate if TSL unavailable.
    --ocsp-url=URL             URL for the OCSP server.
    --mobile-id-url=URL        Custom URL for Mobile-Id API.
  	--mobile-id-user=NAME      Username (relying party name) for Mobile Id.
  	--mobile-id-password=UUID  Password (relying party UUID) for Mobile Id.
  	--timemark                 Get the Estonian BDOC's timemark with OCSP.
  	--timestamp                Get a timestamp on the signature.
    --timestamp-url=URL        URL for the timestamp server.
    --type=MIME                Override mime type of file.
`.trimLeft()

module.exports = _.compose(errorify, co.wrap(function*(argv) {
	var args = Neodoc.run(USAGE_TEXT, {argv: argv})
	if (args["--help"]) return void process.stdout.write(USAGE_TEXT)
	var path = args["<file>"]
	if (path == null) return void process.stdout.write(USAGE_TEXT)

	var mobileId = args["--mobile-id-user"] || args["--mobile-id-url"]
		? new MobileId(args["--mobile-id-url"], {
			user: args["--mobile-id-user"],
			password:  args["--mobile-id-password"]
		})
		: MobileId.demo

	var phoneNumber = args["--phone"]
	var personalId = args["--id"]

	var tslPath = args["--tsl"]
	var issuerPath = args["--issuer"]

	if (!(tslPath || issuerPath))
		throw new Error("Pass either --tsl or <issuer-certificate>")

	var cert = yield mobileId.certificate(phoneNumber, personalId)
	var tsl = tslPath && Tsl.parse(Fs.readFileSync(tslPath))
	var issuer = issuerPath && Certificate.parse(Fs.readFileSync(issuerPath))
	if (issuer == null) issuer = tsl.certificates.getIssuer(cert)

	if (issuer == null) throw new Error(
		"Can't find issuer: " + cert.issuerDistinguishedName.join(", ")
	)

	var xades = new Xades(cert, [{
		path: path,
		type: args["--type"] || Mime.lookup(path),
		hash: yield sha256Stream(Fs.createReadStream(path))
	}], {policy: args["--timemark"] ? "bdoc" : null})

	console.warn(
		"Confirmation code: " + serializeConfirmation(xades.signableHash)
	)

	var session = yield mobileId.sign(
		phoneNumber,
		personalId,
		xades.signableHash
	)

	var signature = yield mobileId.wait(session)
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
		if (err instanceof MobileIdError) {
			process.exitCode = 3
			console.error("Mobile-Id Error: %s: %s", err.code, err.message)
		}
		else throw err
	})
}

function serializeConfirmation(signableHash) {
	return ("000" + MobileId.confirmation(signableHash)).slice(-4)
}
