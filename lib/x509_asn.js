var _ = require("./underscore")
var Asn = require("asn1.js")
var X509Asn = require("asn1.js-rfc5280")
var hash = require("./crypto").hash
exports = module.exports = Object.create(X509Asn)
exports.OCSP_URL = [1, 3, 6, 1, 5, 5, 7, 48, 1]

// https://tools.ietf.org/html/rfc3279 MD5, SHA1, ECDSA with SHA1
// https://tools.ietf.org/html/rfc5758 SHA224+, ECDSA with SHA224+
// https://tools.ietf.org/html/rfc7427 RSA with SHA256+
// https://tools.ietf.org/html/rfc4055 RSA with SHA224
var CRYPTO_OIDS = {
	dsa: [1, 2, 840, 10040, 4, 1],
	rsa: [1, 2, 840, 113549, 1, 1, 1],
	ecdsa: [1, 2, 840, 10045, 2, 1],
}

var HASH_OIDS = {
	sha1: [1, 3, 14, 3, 2, 26],
	sha224: [2, 16, 840, 1, 101, 3, 4, 2, 4],
	sha256: [2, 16, 840, 1, 101, 3, 4, 2, 1],
	sha384: [2, 16, 840, 1, 101, 3, 4, 2, 2],
	sha512: [2, 16, 840, 1, 101, 3, 4, 2, 3]
}

var SIGNATURE_OIDS = {
	"dsa-sha1": [1, 2, 840, 10040, 4, 3],
	"dsa-sha224": [2, 16, 840, 1, 101, 3, 4, 3, 1],
	"dsa-sha256": [2, 16, 840, 1, 101, 3, 4, 3, 2],
	"rsa-sha1": [1, 2, 840, 113549, 1, 1, 5],
	"rsa-sha224": [1, 2, 840, 113549, 1, 1, 14],
	"rsa-sha256": [1, 2, 840, 113549, 1, 1, 11],
	"rsa-sha384": [1, 2, 840, 113549, 1, 1, 12],
	"rsa-sha512": [1, 2, 840, 113549, 1, 1, 13],
	"ecdsa-sha1": [1, 2, 840, 10045, 4, 1],
	"ecdsa-sha224": [1, 2, 840, 10045, 4, 3, 1],
	"ecdsa-sha256": [1, 2, 840, 10045, 4, 3, 2],
	"ecdsa-sha384": [1, 2, 840, 10045, 4, 3, 3],
	"ecdsa-sha512": [1, 2, 840, 10045, 4, 3, 4]
}

// https://tools.ietf.org/html/rfc3279#section-2.3.5 EcpkParameters
// https://tools.ietf.org/html/rfc5480
var EC_OIDS = {
	c2pnb163v1: [1, 2, 840, 10045, 3, 0, 1],
	c2pnb163v2: [1, 2, 840, 10045, 3, 0, 2],
	c2pnb163v3: [1, 2, 840, 10045, 3, 0, 3],
	c2pnb176w1: [1, 2, 840, 10045, 3, 0, 4],
	c2tnb191v1: [1, 2, 840, 10045, 3, 0, 5],
	c2tnb191v2: [1, 2, 840, 10045, 3, 0, 6],
	c2tnb191v3: [1, 2, 840, 10045, 3, 0, 7],
	c2onb191v4: [1, 2, 840, 10045, 3, 0, 8],
	c2onb191v5: [1, 2, 840, 10045, 3, 0, 9],
	c2pnb208w1: [1, 2, 840, 10045, 3, 0, 10],
	c2tnb239v1: [1, 2, 840, 10045, 3, 0, 11],
	c2tnb239v2: [1, 2, 840, 10045, 3, 0, 12],
	c2tnb239v3: [1, 2, 840, 10045, 3, 0, 13],
	c2onb239v4: [1, 2, 840, 10045, 3, 0, 14],
	c2onb239v5: [1, 2, 840, 10045, 3, 0, 15],
	c2pnb272w1: [1, 2, 840, 10045, 3, 0, 16],
	c2pnb304w1: [1, 2, 840, 10045, 3, 0, 17],
	c2tnb359v1: [1, 2, 840, 10045, 3, 0, 18],
	c2pnb368w1: [1, 2, 840, 10045, 3, 0, 19],
	c2tnb431r1: [1, 2, 840, 10045, 3, 0, 20],
	prime192v1: [1, 2, 840, 10045, 3, 1, 1],
	prime192v2: [1, 2, 840, 10045, 3, 1, 2],
	prime192v3: [1, 2, 840, 10045, 3, 1, 3],
	prime239v1: [1, 2, 840, 10045, 3, 1, 4],
	prime239v2: [1, 2, 840, 10045, 3, 1, 5],
	prime239v3: [1, 2, 840, 10045, 3, 1, 6],
	prime256v1: [1, 2, 840, 10045, 3, 1, 7]
}

exports.CRYPTO_OIDS = CRYPTO_OIDS
exports.CRYPTO_NAMES = indexOids(CRYPTO_OIDS)
exports.HASH_OIDS = HASH_OIDS
exports.HASH_NAMES = indexOids(HASH_OIDS)
exports.SIGNATURE_OIDS = SIGNATURE_OIDS
exports.SIGNATURE_NAMES = indexOids(SIGNATURE_OIDS)
exports.EC_OIDS = EC_OIDS
exports.EC_NAMES = indexOids(EC_OIDS)

_.assign(exports, _.mapKeys(CRYPTO_OIDS, toConstantName))
_.assign(exports, _.mapKeys(HASH_OIDS, toConstantName))
_.assign(exports, _.mapKeys(SIGNATURE_OIDS, toConstantName))

var DigestInfo = Asn.define("DigestInfo", function() {
	this.seq().obj(
    this.key("digestAlgorithm").use(X509Asn.AlgorithmIdentifier),
    this.key("digest").octstr()
	)
})

exports.DigestInfo = DigestInfo

// https://www.ietf.org/rfc/rfc5480.txt
var EcSignature = Asn.define("EcSignature", function() {
	this.seq().obj(
		this.key("r").int(),
		this.key("s").int()
	)
})

exports.EcSignature = EcSignature

// https://www.ietf.org/rfc/rfc5480.txt
var EcParameters = Asn.define("EcParameters", function() {
	this.seq().choice({
		ecParameters: this.seq().obj(
			this.key("version").int()
		),

		namedCurve: this.objid(exports.EC_NAMES),
		implicitlyCA: this.null_()
	})
})

exports.EcParameters = EcParameters

exports.digest = function(algorithm, data) {
	var oid = HASH_OIDS[algorithm]
	if (oid == null) throw new RangeError("Unknown algorithm: " + algorithm)

	return DigestInfo.encode({
		digestAlgorithm: {algorithm: oid},
		digest: hash(algorithm, data)
	})
}

function indexOids(oids) {
	return Object.keys(oids).reduce((obj, name) => (
		obj[oids[name].join(".")] = name, obj
	), {})
}

function toConstantName(name) { return name.toUpperCase().replace(/-/g, "_") }
