var Fs = require("fs")
var Neodoc = require("neodoc")
var Xades = require("../xades")
var co = require("co")
var outdent = require("../lib/outdent")
var slurp = require("../lib/stream").slurp

var USAGE_TEXT = `
Usage: hades validate (-h | --help)
       hades validate [options] [<signature-file>|-]

Options:
    -h, --help           Display this help and exit.
`.trimLeft()

exports = module.exports = co.wrap(function*(argv) {
	var args = Neodoc.run(USAGE_TEXT, {argv: argv})
	if (args["--help"]) return void process.stdout.write(USAGE_TEXT)

	var sigPath
	if (args["-"]) sigPath = "-"
	else if ("<signature-file>" in args) sigPath = args["<signature-file>"]
	if (sigPath == null) return void process.stdout.write(USAGE_TEXT)

	var sigStream = sigPath == "-" ? process.stdin : Fs.createReadStream(sigPath)
	var xades = Xades.parse(yield slurp(sigStream))
	var certificate = xades.certificate

	console.log(outdent`
		Public Key Algorithm: ${(
			certificate.publicKeyAlgorithmName ||
			certificate.publicKeyAlgorithm
		).toUpperCase()}
	`)

	if (certificate.hasSigned(xades.signable, xades.signature))
		console.log("Signature: OK")
	else
		console.log("Signature: Invalid")
})
