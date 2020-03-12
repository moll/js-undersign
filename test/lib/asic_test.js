var Asic = require("../../lib/asic")
var Yauzl = require("yauzl")
var ManifestXml = require("../../lib/manifest_xml")
var slurp = require("../../lib/stream").slurp
var ASICE_TYPE = "application/vnd.etsi.asic-e+zip"

describe("Asic", function() {
	describe("new", function() {
		it("must return a new Asic instance", function() {
			new Asic().must.be.an.instanceof(Asic)
		})

		it("must have type set to the ASIC-E MIME type", function() {
			new Asic().type.must.equal(ASICE_TYPE)
		})

		it("must zip a mimetype file first", function*() {
			var zip = yield parseZip(yield new Asic().toBuffer())
			var entries = yield parseZipEntries(zip)

			entries.mimetype.isCompressed().must.be.false()
			yield readZipEntry(zip, entries.mimetype).must.then.equal(ASICE_TYPE)
		})

		it("must zip a manifest file even if empty", function*() {
			var zip = yield parseZip(yield new Asic().toBuffer())
			var entries = yield parseZipEntries(zip)
			Object.keys(entries).length.must.equal(2)

			var entry = entries["META-INF/manifest.xml"]
			var manifest = ManifestXml.parse(yield readZipEntry(zip, entry))

			var file = manifest.m$manifest["m$file-entry"]
			file["m$media-type"].must.equal(ASICE_TYPE)
			file["m$full-path"].must.equal("/")
		})
	})

	describe(".prototype.add", function() {
		it("must support non-ASCII characters", function*() {
			var asic = new Asic
			asic.add("Ööpääsuke 🐦.txt", "Hello, 🌍!", "text/plain")

			var zip = yield parseZip(yield asic.toBuffer())
			var entries = yield parseZipEntries(zip)
			Object.keys(entries).length.must.equal(3)

			var manifestEntry = entries["META-INF/manifest.xml"]
			var manifest = ManifestXml.parse(yield readZipEntry(zip, manifestEntry))
			var files = manifest.m$manifest["m$file-entry"]
			files.length.must.equal(2)

			files[0]["m$media-type"].must.equal(ASICE_TYPE)
			files[0]["m$full-path"].must.equal("/")
			files[1]["m$media-type"].must.equal("text/plain")
			files[1]["m$full-path"].must.equal("Ööpääsuke 🐦.txt")

			var document = yield readZipEntry(zip, entries["Ööpääsuke 🐦.txt"])
			document.must.equal("Hello, 🌍!")
		})
	})

	describe(".prototype.addSignature", function() {
		it("must add signature files with incrementing ids", function*() {
			var asic = new Asic
			asic.addSignature("signature-xml-1")
			asic.addSignature("signature-xml-2")
			asic.addSignature("signature-xml-3")
			asic.add("document.txt", "Hello, world!", "text/plain")

			var zip = yield parseZip(yield asic.toBuffer())
			var entries = yield parseZipEntries(zip)
			Object.keys(entries).length.must.equal(6)

			yield Promise.all([
				readZipEntry(zip, entries["META-INF/signatures-1.xml"]),
				readZipEntry(zip, entries["META-INF/signatures-2.xml"]),
				readZipEntry(zip, entries["META-INF/signatures-3.xml"])
			]).must.then.eql([
				"signature-xml-1",
				"signature-xml-2",
				"signature-xml-3"
			])

			// Signatures are not in the manifest.
			var manifestEntry = entries["META-INF/manifest.xml"]
			var manifest = ManifestXml.parse(yield readZipEntry(zip, manifestEntry))
			var files = manifest.m$manifest["m$file-entry"]
			files.length.must.equal(2)

			files[0]["m$media-type"].must.equal(ASICE_TYPE)
			files[0]["m$full-path"].must.equal("/")
			files[1]["m$media-type"].must.equal("text/plain")
			files[1]["m$full-path"].must.equal("document.txt")
		})
	})

	describe(".prototype.toStream", function() {
		it("must return a ZIP file", function*() {
			var asic = new Asic
			asic.end()
			var stream = asic.toStream()
			var zip = yield parseZip(yield slurp(stream))
			zip.must.be.an.instanceof(Yauzl.ZipFile)
		})
	})

	describe(".prototype.toBuffer", function() {
		it("must return a ZIP file", function*() {
			var zip = yield parseZip(yield new Asic().toBuffer())
			zip.must.be.an.instanceof(Yauzl.ZipFile)
		})
	})

	describe(".prototype.end", function() {
		it("must permit calling Asic.prototype.end multiple times", function*() {
			var asic = new Asic
			asic.add("document.txt", "Hello, world!", "text/plain")
			asic.end()
			asic.end()

			var zip = yield parseZip(yield asic.toBuffer())
			var entries = yield parseZipEntries(zip)
			Object.keys(entries).length.must.equal(3)
		})
	})
})

function parseZipEntries(zip) {
	var entries = {}
	zip.on("entry", (entry) => (entries[entry.fileName] = entry))

	return new Promise(function(resolve, reject) {
		zip.on("error", reject)
		zip.on("end", resolve.bind(null, entries))
	})
}

function readZipEntry(zip, entry) {
	return new Promise(function(resolve, reject) {
		zip.openReadStream(entry, (err, stream) => (
			err ? reject(err) : resolve(slurp(stream, "utf8"))
		))
	})
}

function* parseZip(buffer) { return yield Yauzl.fromBuffer.bind(null, buffer) }
